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

	args, env, err := requesterInfo(parent)
	if err != nil {
		logger.Printf("couldn't read the requesting process: %v", err)
	}
	if executable, _ := executableOf(parent); underEmulator(executable) {
		args = nil
	}
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
	if strings.HasPrefix(service, "sudo") {
		if err := checkSudoProgram(args, env); err != nil {
			tell("%v; type your password.", err)
			return 1
		}
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
	// The device id itself comes from the agent; approvers.json only has its hash, which matched.
	if err != nil || !validSignature(key, approvalMessage(approvers.MachineID, message.DeviceID, approval), message.Signature) {
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
	if id == "" {
		return nil
	}
	return a.findKey(deviceIDHash(id))
}

func (a *Approvers) findKey(key string) *Approver {
	for i := range a.Devices {
		if a.Devices[i].key() == key {
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
	return checkFolders(filepath.Dir(path))
}

// checkFolders: dir and every folder above it belong to root (or whoever runs this) and nobody else can write to
// them, so nobody else can swap what's inside.
func checkFolders(dir string) error {
	for ; ; dir = filepath.Dir(dir) {
		info, err := os.Stat(dir)
		if err != nil {
			return err
		}
		if !ownedByRoot(info) {
			return fmt.Errorf("%s must belong to root", dir)
		}
		if writableByOthers(info) {
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

// requesterInfo reads the requesting process's arguments and environment; tests replace it.
var requesterInfo = processInfo

// underEmulator: sudo runs through binfmt emulation (Rosetta in Docker on a Mac, qemu-user). Its arguments then read
// differently depending on whether this checker is emulated too ([sudo, -k, …]) or not ([/run/rosetta/rosetta,
// /usr/sbin/sudo, sudo, -k, …], or without sudo's own first argument for qemu without preserve-argv0), and whoever
// starts sudo can make one look like the other. So such a request gets the password prompt. It goes by the program
// the process runs, never by the first argument, which whoever starts sudo chooses.
func underEmulator(executable string) bool {
	base := filepath.Base(executable)
	return base == "rosetta" || strings.HasPrefix(base, "qemu-")
}

// sudoWithoutPrompt: `sudo -S` (password from stdin, as scripts use it) and `sudo -n` (never prompt) shouldn't
// wait for the iPhone.
func sudoWithoutPrompt(args []string) bool {
	return parseSudo(args).noPrompt
}

// sudoCommandLine is what the checker needs from sudo's arguments.
type sudoCommandLine struct {
	noPrompt bool // -S or -n
	shell    bool // -s: runs $SHELL
	login    bool // -i: root's own login shell
	edit     bool // -e, sudoedit: edits copies as you
	// -E, or --preserve-env without a list: passes your whole environment on to the command.
	preserveEnv bool
	// From the command on, after any VAR=value settings.
	command []string
}

func parseSudo(args []string) sudoCommandLine {
	var line sudoCommandLine
	if len(args) == 0 {
		return line
	}
	line.edit = filepath.Base(args[0]) == "sudoedit"
	i := 1
options:
	for ; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			i++
			break options
		case strings.HasPrefix(arg, "--"):
			name, _, hasValue := strings.Cut(arg, "=")
			switch name {
			case "--stdin", "--non-interactive":
				line.noPrompt = true
			case "--shell":
				line.shell = true
			case "--login":
				line.login = true
			case "--edit":
				line.edit = true
			case "--preserve-env":
				line.preserveEnv = line.preserveEnv || !hasValue
			}
			if !hasValue && sudoLongOptionTakesValue(name) {
				i++
			}
		case strings.HasPrefix(arg, "-") && len(arg) > 1:
			for j, flag := range arg[1:] {
				switch flag {
				case 'S', 'n':
					line.noPrompt = true
				case 's':
					line.shell = true
				case 'i':
					line.login = true
				case 'e':
					line.edit = true
				case 'E':
					line.preserveEnv = true
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
			break options // the command starts here
		}
	}
	// sudo takes leading words with an = as environment variables for the command.
	for i < len(args) && strings.IndexByte(args[i], '=') > 0 {
		i++
	}
	if i < len(args) {
		line.command = args[i:]
	}
	return line
}

// checkSudoProgram makes sure the program sudo runs as root is the one the iPhone names. sudo looks a name up in
// the PATH it was started with (unless sudoers sets secure_path, which macOS and Arch don't), so otherwise a
// program running as you could put its own `ls` in a folder you can write to, such as Homebrew's, or start sudo
// with such a PATH, and get "sudo ls -la" approved. So the program, and every folder on the way to it, must be
// root's. What's left is a race: removing that `ls` between sudo's lookup and this one, and putting it back after.
func checkSudoProgram(args []string, env map[string]string) error {
	line := parseSudo(args)
	switch {
	case line.edit:
		return nil // the editor runs as you, on a copy
	case line.preserveEnv:
		return errors.New("sudo -E passes your whole environment on, which can change what the command does")
	case line.login:
		return nil // root's own shell, with root's PATH
	}
	if line.shell {
		// Without SHELL sudo runs your shell from the user database, which only root can change.
		if env == nil {
			return errors.New("couldn't tell which shell sudo -s runs")
		}
		if shell := env["SHELL"]; shell != "" {
			if err := checkProgram(shell); err != nil {
				return err
			}
		}
	}
	if len(line.command) == 0 {
		return nil
	}
	program, err := lookPath(line.command[0], env)
	if err != nil {
		return err
	}
	return checkProgram(program)
}

// lookPath finds a command the way sudo does: a word with a slash is the program's path, any other is looked up in
// sudo's PATH. With secure_path set, sudo uses that instead, which only has root's folders.
func lookPath(name string, env map[string]string) (string, error) {
	if strings.Contains(name, "/") {
		if !filepath.IsAbs(name) {
			return "", fmt.Errorf("couldn't tell which program %s is", name)
		}
		return name, nil
	}
	path, ok := env["PATH"]
	if !ok {
		return "", fmt.Errorf("couldn't tell which program %s is", name)
	}
	for _, dir := range filepath.SplitList(path) {
		if !filepath.IsAbs(dir) {
			return "", fmt.Errorf("couldn't tell which program %s is (PATH has %q)", name, dir)
		}
		program := filepath.Join(dir, name)
		if info, err := os.Stat(program); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return program, nil
		}
	}
	return "", fmt.Errorf("couldn't find %s", name)
}

// checkProgram walks path the way running it does, one name at a time and through every symbolic link, and checks
// that each folder, link and the program itself belongs to root (or whoever runs this) and that nobody else can
// change it: no folder others can write to, except sticky ones like /tmp, where they can't rename root's entries.
// Otherwise "sudo would run …" says which program another one running as you could swap.
func checkProgram(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("couldn't tell which program %s is", path)
	}
	unsafe := fmt.Errorf("sudo would run %s, which programs running as you can change", path)
	if info, err := os.Lstat("/"); err != nil || !ownedByRoot(info) || writableByOthers(info) {
		return unsafe
	}
	dir, names := "/", strings.Split(path, "/")
	for links := 0; len(names) > 0; {
		name := names[0]
		names = names[1:]
		if !isName(name) {
			continue
		}
		next := filepath.Join(dir, name)
		info, err := os.Lstat(next)
		if err != nil || !ownedByRoot(info) {
			return unsafe
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			links++
			target, err := os.Readlink(next)
			if err != nil || links > 40 {
				return unsafe
			}
			if filepath.IsAbs(target) {
				dir = "/"
			}
			names = append(strings.Split(target, "/"), names...)
		case info.IsDir():
			if writableByOthers(info) {
				return unsafe
			}
			dir = next
		default:
			// The program: a file nobody else can change, with nothing after it.
			if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
				return unsafe
			}
			for _, name := range names {
				if isName(name) {
					return unsafe
				}
			}
			return nil
		}
	}
	return unsafe // a folder, not a program
}

func isName(part string) bool {
	return part != "" && part != "."
}

// ownedByRoot: or by whoever runs this (root, in real use; the tests run as you).
func ownedByRoot(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (stat.Uid == 0 || int(stat.Uid) == os.Geteuid())
}

// writableByOthers: others can swap what's in the folder, as it isn't sticky.
func writableByOthers(folder os.FileInfo) bool {
	return folder.Mode().Perm()&0o022 != 0 && folder.Mode()&os.ModeSticky == 0
}

func sudoLongOptionTakesValue(option string) bool {
	switch option {
	case "--close-from", "--chdir", "--group", "--host", "--prompt", "--chroot", "--role", "--type",
		"--command-timeout", "--other-user", "--user":
		return true
	}
	return false
}

var (
	errTitleTooLong   = errors.New("the command is too long to show on your iPhone in full; type your password.")
	errUnknownCommand = errors.New("couldn't tell which command this is; type your password.")
)

// polkitTitle: polkit doesn't tell PAM what the dialog is for, so the iPhone can only say where to look.
const polkitTitle = "Password dialog (check your screen for what it's for)"

// describeRequest makes the one-line title and detail the iPhone shows (and signs). The title shows the whole
// command or nothing: a command that doesn't fit gets the password prompt instead, rather than an approval for
// a beginning that could hide what follows.
func describeRequest(service, username, tty string, args []string) (title, detail string, err error) {
	switch {
	case strings.HasPrefix(service, "sudo"):
		// Only sudo's own arguments: anything else (unreadable, or a first argument that isn't sudo) could make
		// the iPhone show something other than what runs.
		if len(args) == 0 {
			return "", "", errUnknownCommand
		}
		var words []string
		switch filepath.Base(args[0]) {
		case "sudo", "sudo-rs":
			words = []string{"sudo"}
		case "sudoedit":
			words = []string{"sudoedit"}
		default:
			return "", "", errUnknownCommand
		}
		for _, arg := range args[1:] {
			if arg == "" || !utf8.ValidString(arg) || strings.IndexFunc(arg, needsQuotes) >= 0 {
				arg = quote(arg)
			}
			words = append(words, arg)
		}
		title = strings.Join(words, " ")
	case service == "polkit-1":
		title = polkitTitle
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
// such as right-to-left overrides and zero-width spaces, blank-looking letters, and the replacement character,
// which oneLine turns into a space. quote shows those as escapes like \u202e.
func needsQuotes(r rune) bool {
	return r <= ' ' || strings.ContainsRune(`'"\`, r) || unicode.IsSpace(r) || !unicode.IsGraphic(r) || looksBlank(r) ||
		r == utf8.RuneError
}

// looksBlank: characters that count as letters or symbols but show as nothing or a space, like the Hangul fillers,
// the combining grapheme joiner and the Braille blank, which strconv.Quote leaves as they are.
func looksBlank(r rune) bool {
	return unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) || unicode.Is(unicode.Variation_Selector, r) || r == '\u2800'
}

// quote is strconv.Quote, which escapes control and invisible characters, plus escapes for the ones it leaves: the
// blank-looking ones and the replacement character, which oneLine would make a space.
func quote(arg string) string {
	var out strings.Builder
	for _, r := range strconv.Quote(arg) {
		switch {
		case r > 0xffff && looksBlank(r):
			fmt.Fprintf(&out, `\U%08x`, r)
		case looksBlank(r) || r == utf8.RuneError:
			fmt.Fprintf(&out, `\u%04x`, r)
		default:
			out.WriteRune(r)
		}
	}
	return out.String()
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
