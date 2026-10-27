package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

// `<agent> pam` is the checker that sudo and polkit run through PAM, as root: pam_exec on Linux, the PAM
// module in Mac/PAM on the Mac. It asks your agent (or the Mac app) to show the request
// on your iPhone, then checks the iPhone's signature itself against approvers.json, which only root can change.
// The agent and the relay only carry messages, so neither can approve anything. Exit status 0 lets PAM skip the
// password; anything else falls through to the normal password prompt.

const (
	approversPath       = "/etc/" + appID + "/approvers.json"
	checkerInstallPath  = "/usr/local/libexec/" + appID + "/" + agentCommand
	defaultApprovalWait = 30 * time.Second
	// The agent and the Mac app take up to 300; the iPhone shows all of it.
	maxTitleLength = 300
)

func runChecker(args []string) int {
	flags := flag.NewFlagSet("pam", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	approversFile := flags.String("approvers", approversPath, "")
	socket := flags.String("socket", "", "")
	wait := flags.Duration("timeout", defaultApprovalWait, "")
	allowRemote := flags.Bool("allow-remote", false, "")
	check := flags.Bool("check", false, "")
	if flags.Parse(args) != nil || *wait < time.Second || *wait > maxApprovalWait {
		return 2
	}
	logger := checkerLog()

	approvers, err := loadApprovers(*approversFile)
	if err != nil {
		logger.Printf("not set up: %v", err)
		if *check {
			tell("%v", err)
		}
		return 1
	}
	if *check {
		tell("%d iPhone(s) can approve on %s.", len(approvers.Devices), approvers.MachineName)
		return 0
	}
	if pamType := os.Getenv("PAM_TYPE"); pamType != "" && pamType != "auth" {
		return 1
	}
	username, service := os.Getenv("PAM_USER"), os.Getenv("PAM_SERVICE")
	account, err := user.Lookup(username)
	if username == "" || err != nil {
		return 1
	}

	// sudo (or polkit's helper) is the parent. If it dies, for example killed while waiting, stop too, so the
	// request disappears from the iPhone.
	parent := os.Getppid()
	done := make(chan struct{})
	defer close(done)
	go exitWithParent(parent, done)

	args, env, err := processInfo(parent)
	if err != nil {
		logger.Printf("couldn't read the requesting process: %v", err)
	}
	args = withoutEmulator(args)
	if !*allowRemote && (isRemote(env) || remoteAncestor(parent)) {
		return 1
	}
	if strings.HasPrefix(service, "sudo") && sudoWithoutPrompt(args) {
		return 1
	}
	title, detail, err := describeRequest(service, username, os.Getenv("PAM_TTY"), args)
	if err != nil {
		tell("%v", err)
		return 1
	}
	approval := Approval{ID: randomToken(12), Nonce: randomToken(32), Title: title, Detail: detail, ExpiresIn: int(*wait / time.Second)}

	path := *socket
	if path == "" {
		path = agentSocketFor(account)
	}
	uid, _ := strconv.Atoi(account.Uid)
	if err := checkSocket(path, uid); err != nil {
		logger.Printf("%v", err)
		return 1
	}
	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		logger.Printf("couldn't reach %s: %v", appName, err)
		return 1
	}
	defer conn.Close()
	encoder, decoder := json.NewEncoder(conn), json.NewDecoder(conn)

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	var message checkerMessage
	if encoder.Encode(controlRequest{Command: "approval", Approval: &approval}) != nil || decoder.Decode(&message) != nil || !message.Waiting {
		logger.Printf("%s can't ask the iPhone: %s", appName, message.Error)
		return 1
	}
	// This computer's approval wait, from the agent (wait.go).
	waitFor := *wait
	if seconds := time.Duration(message.ExpiresIn) * time.Second; seconds > 0 && seconds <= maxApprovalWait {
		waitFor = seconds
	}
	enter := pressedEnter()
	forever := waitFor >= maxApprovalWait
	switch {
	case enter != nil && forever:
		tell("approve on your iPhone, or press Enter to type your password.")
	case enter != nil:
		tell("approve on your iPhone, or press Enter to type your password (it waits %s).", describeApprovalWait(int(waitFor/time.Second)))
	case forever:
		tell("approve on your iPhone.")
	default:
		tell("approve on your iPhone, or wait %s to type your password.", describeApprovalWait(int(waitFor/time.Second)))
	}

	conn.SetDeadline(time.Now().Add(waitFor + 5*time.Second))
	answers := make(chan checkerMessage, 1)
	go func() {
		var answer checkerMessage
		if decoder.Decode(&answer) != nil && answer.Error == "" {
			answer.Error = "no answer"
		}
		answers <- answer
	}()
	select {
	case <-enter:
		// Hanging up takes the request off the iPhone; sudo asks for the password next.
		return 1
	case message = <-answers:
	}
	if message.Error != "" {
		tell("no answer from your iPhone.")
		return 1
	}
	switch message.Decision {
	case string(actionDeny):
		tell("denied on your iPhone.")
		return 1
	case string(actionApprove):
		accepted, problem := verifyApproval(approvers, approval, message)
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		encoder.Encode(checkerMessage{Accepted: &accepted, Error: problem})
		if !accepted {
			tell("%s", problem)
			logger.Printf("rejected an approval: %s", problem)
			return 1
		}
		name := message.DeviceID
		if device := approvers.find(message.DeviceID); device != nil {
			name = device.Name
		}
		tell("approved on %s.", name)
		logger.Printf("%s approved %s for %s", name, service, username)
		return 0
	}
	return 1
}

// pressedEnter reports Enter on the terminal sudo runs in, so you can type your password instead of waiting. nil
// without one (polkit's dialogs, sudo in a script).
func pressedEnter() <-chan struct{} {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return nil
	}
	pressed := make(chan struct{})
	go func() {
		defer tty.Close()
		buffer := make([]byte, 1)
		for {
			if _, err := tty.Read(buffer); err != nil {
				return
			}
			if buffer[0] == '\n' || buffer[0] == '\r' {
				close(pressed)
				return
			}
		}
	}()
	return pressed
}

// tell prints a line for you in the terminal; PAM passes the checker's output on (pam_exec's stdout option, or
// the Mac's PAM module).
func tell(format string, args ...any) {
	fmt.Printf("%s: %s\n", appName, fmt.Sprintf(format, args...))
}

func verifyApproval(approvers *Approvers, approval Approval, message checkerMessage) (bool, string) {
	device := approvers.find(message.DeviceID)
	if device == nil {
		return false, "this iPhone isn't allowed to approve here yet. " + enableSudoHint()
	}
	key, err := parsePublicKey(device.PublicKey)
	if err != nil || !validSignature(key, approvalMessage(approvers.MachineID, device.ID, approval), message.Signature) {
		return false, "the computer rejected this iPhone's signature."
	}
	return true, ""
}

func enableSudoHint() string {
	if runtime.GOOS == "darwin" {
		return "Run scripts/enable-mac-sudo.sh on the Mac again."
	}
	return "Run `sudo " + agentCommand + " enable-sudo` again."
}

func (a *Approvers) find(id string) *Approver {
	for i := range a.Devices {
		if a.Devices[i].ID == id {
			return &a.Devices[i]
		}
	}
	return nil
}

// loadApprovers reads approvers.json, which must belong to the user running the checker (root, in real use)
// and be writable by nobody else, like the folders above it. Otherwise anyone could add their own key.
func loadApprovers(path string) (*Approvers, error) {
	if err := checkTree(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var approvers Approvers
	if err := json.Unmarshal(data, &approvers); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if approvers.MachineID == "" || len(approvers.Devices) == 0 {
		return nil, fmt.Errorf("%s lists no iPhones", path)
	}
	return &approvers, nil
}

// checkTree checks that path is a file of this user (root, in real use) that nobody else can change or swap:
// neither it nor any folder above it may be writable by others, except sticky folders like /tmp.
func checkTree(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	switch {
	case !info.Mode().IsRegular():
		return fmt.Errorf("%s isn't a regular file", path)
	case !ok || int(stat.Uid) != os.Geteuid():
		return fmt.Errorf("%s must belong to %s", path, currentUserName())
	case info.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("%s must not be writable by others", path)
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		info, err := os.Stat(dir)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != 0 && int(stat.Uid) != os.Geteuid()) {
			return fmt.Errorf("%s must belong to root", dir)
		}
		if info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("%s must not be writable by others", dir)
		}
		if dir == filepath.Dir(dir) {
			return nil
		}
	}
}

// checkSocket makes sure the socket is the user's own, so the checker doesn't talk to anything else.
func checkSocket(path string, uid int) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%s isn't running: %w", appName, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if info.Mode()&os.ModeSocket == 0 || !ok || int(stat.Uid) != uid {
		return fmt.Errorf("%s isn't the user's %s socket", path, appName)
	}
	return nil
}

// agentSocketFor is where the user's agent (on a Mac, the app) listens.
func agentSocketFor(account *user.User) string {
	if runtime.GOOS == "darwin" {
		return filepath.Join(account.HomeDir, "Library", "Application Support", appID, "agent.sock")
	}
	return filepath.Join("/run/user", account.Uid, agentCommand+".sock")
}

func exitWithParent(parent int, done <-chan struct{}) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if os.Getppid() != parent {
				os.Exit(1)
			}
		}
	}
}

// isRemote: approvals are for sessions at the computer itself, not SSH logins. This is a convenience default,
// not a security boundary: the iPhone still shows exactly what it approves.
func isRemote(env map[string]string) bool {
	for _, name := range []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"} {
		if env[name] != "" {
			return true
		}
	}
	return false
}

// remoteAncestor looks for an SSH or mosh server above the process. It also works where the environment of
// a setuid process like sudo can't be read (e.g. in containers without CAP_SYS_PTRACE).
func remoteAncestor(pid int) bool {
	for i := 0; i < 64 && pid > 1; i++ {
		parent, name, err := parentOf(pid)
		if err != nil {
			return false
		}
		switch name {
		case "sshd", "sshd-session", "sshd-auth", "mosh-server":
			return true
		}
		pid = parent
	}
	return false
}

// withoutEmulator drops the interpreter that binfmt emulation (Rosetta in Docker on a Mac, qemu-user) puts in
// front of the arguments: [/run/rosetta/rosetta, /usr/sbin/sudo, sudo, -k, …].
func withoutEmulator(args []string) []string {
	if len(args) >= 3 {
		if base := filepath.Base(args[0]); base == "rosetta" || strings.HasPrefix(base, "qemu-") {
			return args[2:]
		}
	}
	return args
}

// sudoWithoutPrompt: `sudo -S` (password from stdin, as scripts use it) and `sudo -n` (never prompt) shouldn't
// wait for the iPhone.
func sudoWithoutPrompt(args []string) bool {
	if len(args) < 2 {
		return false
	}
	for i := 1; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			return false
		case arg == "--stdin" || arg == "--non-interactive":
			return true
		case strings.HasPrefix(arg, "--"):
			if !strings.Contains(arg, "=") && sudoLongOptionTakesValue(arg) {
				i++
			}
		case strings.HasPrefix(arg, "-") && len(arg) > 1:
			for j, flag := range arg[1:] {
				if flag == 'S' || flag == 'n' {
					return true
				}
				// Options with a value take the rest of the word, or the next argument.
				if strings.ContainsRune("CDghpRrTtUu", flag) {
					if j == len(arg)-2 {
						i++
					}
					break
				}
			}
		default:
			return false // the command starts here
		}
	}
	return false
}

func sudoLongOptionTakesValue(option string) bool {
	switch option {
	case "--close-from", "--chdir", "--group", "--host", "--prompt", "--chroot", "--role", "--type",
		"--command-timeout", "--other-user", "--user":
		return true
	}
	return false
}

var errTitleTooLong = errors.New("the command is too long to show on your iPhone in full; type your password.")

// describeRequest makes the one-line title and detail the iPhone shows (and signs). The title shows the whole
// command or nothing: a command that doesn't fit gets the password prompt instead, rather than an approval for
// a beginning that could hide what follows.
func describeRequest(service, username, tty string, args []string) (title, detail string, err error) {
	switch {
	case strings.HasPrefix(service, "sudo") && len(args) > 0:
		words := []string{"sudo"}
		for _, arg := range args[1:] {
			if arg == "" || strings.IndexFunc(arg, needsQuotes) >= 0 {
				arg = strconv.Quote(arg)
			}
			words = append(words, arg)
		}
		title = strings.Join(words, " ")
	case service == "polkit-1":
		title = "Administrator access (system dialog)"
	case service != "":
		title = service + " password prompt"
	default:
		title = "Password prompt"
	}
	detail = username
	if tty = strings.TrimPrefix(tty, "/dev/"); tty != "" {
		detail += " on " + tty
	}
	if utf8.RuneCountInString(title) > maxTitleLength {
		return "", "", errTitleTooLong
	}
	return oneLine(title, maxTitleLength), oneLine(detail, 80), nil
}

// needsQuotes: characters that would make an argument look like something else, from spaces to invisible ones
// such as right-to-left overrides and zero-width spaces. strconv.Quote shows those as escapes like \u202e.
func needsQuotes(r rune) bool {
	return r <= ' ' || strings.ContainsRune(`'"\`, r) || unicode.IsSpace(r) || !unicode.IsGraphic(r)
}

// oneLine replaces control characters and line separators with spaces and shortens to limit characters.
func oneLine(text string, limit int) string {
	text = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 || r == utf8.RuneError {
			return ' '
		}
		return r
	}, text)
	if utf8.RuneCountInString(text) > limit {
		text = string([]rune(text)[:limit-1]) + "…"
	}
	return text
}

func currentUserName() string {
	if account, err := user.LookupId(strconv.Itoa(os.Geteuid())); err == nil {
		return account.Username
	}
	return "uid " + strconv.Itoa(os.Geteuid())
}

// checkerLog goes to syslog (journalctl -t <appID>, or the Mac's log), since PAM hides the checker's errors.
func checkerLog() *log.Logger {
	if writer, err := syslog.New(syslog.LOG_AUTH|syslog.LOG_NOTICE, appID); err == nil {
		return log.New(writer, "", 0)
	}
	return log.New(io.Discard, "", 0)
}

// askApprovers gets the paired iPhones from the user's running agent or Mac app.
func askApprovers(socket string) (*Approvers, error) {
	conn, err := net.DialTimeout("unix", socket, 3*time.Second)
	if err != nil {
		return nil, errors.New(appName + " isn't running")
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := json.NewEncoder(conn).Encode(controlRequest{Command: "approvers"}); err != nil {
		return nil, err
	}
	var response controlResponse
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return nil, err
	}
	if response.Error != "" || response.Approvers == nil {
		return nil, fmt.Errorf("unexpected answer: %s", response.Error)
	}
	return response.Approvers, nil
}
