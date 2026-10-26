package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// approvalSetup is an agent with a paired phone, its control socket and an approvers.json, plus the PAM
// environment the checker gets from sudo.
type approvalSetup struct {
	agent     *Agent
	phone     *phone
	socket    string
	approvers string
}

func newApprovalSetup(t *testing.T) *approvalSetup {
	// Short paths: Unix socket paths are limited to about 100 bytes.
	dir, err := os.MkdirTemp("", "fu")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	t.Setenv(envPrefix+"CONFIG_DIR", dir)
	state, err := loadState()
	if err != nil {
		t.Fatal(err)
	}
	agent := newAgent(state, &fakeScreen{}, &memoryPasswords{})
	agent.setRelayStatus("connected")
	phone := newPhone(t, agent)
	token, _ := agent.auth.StartPairing()
	if status, body := phone.pair(token); status != 200 {
		t.Fatalf("pairing: %d %v", status, body)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go agent.serveControl(ctx)
	socket := controlSocketPath()
	waitUntil(t, func() bool { _, err := os.Stat(socket); return err == nil })

	setup := &approvalSetup{agent: agent, phone: phone, socket: socket, approvers: filepath.Join(dir, "approvers.json")}
	approvers, err := askApprovers(socket)
	if err != nil {
		t.Fatal(err)
	}
	setup.writeApprovers(t, approvers)

	account, _ := user.Current()
	t.Setenv("PAM_USER", account.Username)
	t.Setenv("PAM_SERVICE", "sudo")
	t.Setenv("PAM_TTY", "/dev/pts/7")
	t.Setenv("PAM_TYPE", "auth")
	return setup
}

func (s *approvalSetup) writeApprovers(t *testing.T, approvers *Approvers) {
	data, _ := json.Marshal(approvers)
	if err := os.WriteFile(s.approvers, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// check runs the checker the way PAM would and returns its exit status.
func (s *approvalSetup) check(timeout string) chan int {
	result := make(chan int, 1)
	go func() {
		result <- runChecker([]string{"--approvers", s.approvers, "--socket", s.socket, "--timeout", timeout, "--allow-remote"})
	}()
	return result
}

// waitForApproval polls hello like the iPhone app does until the checker's request shows up.
func (p *phone) waitForApproval() Approval {
	var found []Approval
	waitUntil(p.t, func() bool {
		status, body := p.call("/v1/hello", HelloRequest{DeviceID: p.deviceID})
		if status != 200 {
			p.t.Fatalf("hello: %d %v", status, body)
		}
		data, _ := json.Marshal(body["approvals"])
		json.Unmarshal(data, &found)
		return len(found) > 0
	})
	return found[0]
}

func (p *phone) signApproval(approval Approval) string {
	return signWith(p.t, p.key, approvalMessage(p.agent.state.MachineID, p.deviceID, approval))
}

func (p *phone) answer(action Action, approval Approval, signature string) (int, map[string]any) {
	return p.call("/v1/command", CommandRequest{DeviceID: p.deviceID, Action: action, Nonce: approval.Nonce,
		Signature: signature, ApprovalID: approval.ID})
}

func signWith(t *testing.T, key *ecdsa.PrivateKey, message []byte) string {
	digest := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	return base64.StdEncoding.EncodeToString(raw)
}

func waitUntil(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func exitStatus(t *testing.T, result chan int) int {
	t.Helper()
	select {
	case status := <-result:
		return status
	case <-time.After(10 * time.Second):
		t.Fatal("the checker didn't finish")
		return -1
	}
}

func TestApproveRunsThroughChecker(t *testing.T) {
	s := newApprovalSetup(t)
	result := s.check("10s")
	approval := s.phone.waitForApproval()
	if !strings.HasPrefix(approval.Title, "sudo") || !strings.HasSuffix(approval.Detail, "on pts/7") {
		t.Fatalf("unexpected approval %+v", approval)
	}

	// A signature over a different command is rejected, and doesn't use up the request.
	forged := approval
	forged.Title = "sudo rm -rf /"
	if status, _ := s.phone.answer(actionApprove, approval, s.phone.signApproval(forged)); status != 403 {
		t.Fatalf("forged approval: %d", status)
	}
	if status, body := s.phone.answer(actionApprove, approval, s.phone.signApproval(approval)); status != 200 || body["message"] != "Approved" {
		t.Fatalf("approve: %d %v", status, body)
	}
	if status := exitStatus(t, result); status != 0 {
		t.Fatalf("checker exited %d", status)
	}
	if status, _ := s.phone.answer(actionApprove, approval, s.phone.signApproval(approval)); status != 403 {
		t.Fatalf("second answer accepted: %d", status)
	}
}

func TestDenyFallsBackToPassword(t *testing.T) {
	s := newApprovalSetup(t)
	result := s.check("10s")
	approval := s.phone.waitForApproval()
	if status, body := s.phone.answer(actionDeny, approval, ""); status != 200 || body["ok"] != true {
		t.Fatalf("deny: %d %v", status, body)
	}
	if status := exitStatus(t, result); status != 1 {
		t.Fatalf("checker exited %d", status)
	}
}

func TestCheckerOnlyTrustsApprovers(t *testing.T) {
	// The agent knows the phone, but approvers.json (root's list) doesn't: the checker must refuse, since a
	// compromised agent could otherwise approve with a key of its own.
	s := newApprovalSetup(t)
	approvers, _ := askApprovers(s.socket)
	approvers.Devices[0].ID = "someone-else"
	s.writeApprovers(t, approvers)

	result := s.check("10s")
	approval := s.phone.waitForApproval()
	status, body := s.phone.answer(actionApprove, approval, s.phone.signApproval(approval))
	if status != 403 || !strings.Contains(body["error"].(string), "isn't allowed to approve") {
		t.Fatalf("approve: %d %v", status, body)
	}
	if status := exitStatus(t, result); status != 1 {
		t.Fatalf("checker exited %d", status)
	}
}

func TestCheckerRejectsLyingAgent(t *testing.T) {
	// Something pretending to be the agent answers "approved" with a signature from its own key.
	s := newApprovalSetup(t)
	fake := filepath.Join(filepath.Dir(s.socket), "fake.sock")
	listener, err := net.Listen("unix", fake)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var request controlRequest
		json.NewDecoder(conn).Decode(&request)
		encoder := json.NewEncoder(conn)
		encoder.Encode(checkerMessage{Waiting: true})
		attacker := newPhone(t, s.agent)
		encoder.Encode(checkerMessage{Decision: "approve", DeviceID: s.phone.deviceID,
			Signature: signWith(t, attacker.key, approvalMessage(s.agent.state.MachineID, s.phone.deviceID, *request.Approval))})
		io.Copy(io.Discard, conn)
	}()
	status := runChecker([]string{"--approvers", s.approvers, "--socket", fake, "--timeout", "5s", "--allow-remote"})
	if status != 1 {
		t.Fatalf("checker exited %d", status)
	}
}

func TestApprovalTimesOutAndCancels(t *testing.T) {
	s := newApprovalSetup(t)
	start := time.Now()
	if status := exitStatus(t, s.check("1s")); status != 1 || time.Since(start) > 4*time.Second {
		t.Fatalf("timeout: exit %d after %v", status, time.Since(start))
	}
	waitUntil(t, func() bool { return len(s.agent.waitingApprovals()) == 0 })

	// The checker hangs up (Ctrl-C in sudo): the request disappears from the iPhone.
	conn, err := net.Dial("unix", s.socket)
	if err != nil {
		t.Fatal(err)
	}
	approval := Approval{ID: "a", Nonce: "n", Title: "sudo true", Detail: "me", ExpiresIn: 30}
	json.NewEncoder(conn).Encode(controlRequest{Command: "approval", Approval: &approval})
	var message checkerMessage
	if json.NewDecoder(conn).Decode(&message); !message.Waiting {
		t.Fatalf("not waiting: %+v", message)
	}
	if len(s.agent.waitingApprovals()) != 1 {
		t.Fatal("approval not listed")
	}
	conn.Close()
	waitUntil(t, func() bool { return len(s.agent.waitingApprovals()) == 0 })
}

func TestCheckerSkipsWhenPhoneUnreachable(t *testing.T) {
	s := newApprovalSetup(t)
	s.agent.setRelayStatus("offline")
	start := time.Now()
	if status := exitStatus(t, s.check("10s")); status != 1 || time.Since(start) > 2*time.Second {
		t.Fatalf("exit %d after %v", status, time.Since(start))
	}
	os.Remove(s.socket)
	if status := exitStatus(t, s.check("10s")); status != 1 {
		t.Fatalf("without agent: exit %d", status)
	}
}

func TestHelloReportsLockAndSavesPushToken(t *testing.T) {
	screen := &fakeScreen{}
	agent := newTestAgent(t, screen, &memoryPasswords{})
	phone := newPhone(t, agent)
	token, _ := agent.auth.StartPairing()
	phone.pair(token)
	screen.Lock()

	pushToken := strings.Repeat("0123456789abcdef", 4)
	_, body := phone.call("/v1/hello", HelloRequest{DeviceID: phone.deviceID, PushToken: &pushToken})
	if body["locked"] != true {
		t.Fatalf("hello: %v", body)
	}
	if reloaded, _ := loadState(); reloaded.Devices[0].PushToken != pushToken {
		t.Fatal("push token not saved")
	}
	bad := "../../evil"
	phone.call("/v1/hello", HelloRequest{DeviceID: phone.deviceID, PushToken: &bad})
	phone.call("/v1/hello", HelloRequest{DeviceID: phone.deviceID})
	if agent.state.Devices[0].PushToken != pushToken {
		t.Fatal("push token changed by an invalid or missing value")
	}
	empty := ""
	phone.call("/v1/hello", HelloRequest{DeviceID: phone.deviceID, PushToken: &empty})
	if agent.state.Devices[0].PushToken != "" {
		t.Fatal("push token not removed")
	}
}

func TestWaitingApprovalNotifiesThroughRelay(t *testing.T) {
	s := newApprovalSetup(t)
	pushToken := strings.Repeat("0123456789abcdef", 4)
	s.phone.call("/v1/hello", HelloRequest{DeviceID: s.phone.deviceID, PushToken: &pushToken})
	sent := make(chan []byte, 1)
	s.agent.setRelaySender(func(data []byte) error { sent <- data; return nil })

	result := s.check("5s")
	var notification RelayNotification
	select {
	case data := <-sent:
		if err := json.Unmarshal(data, &notification); err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no notification sent")
	}
	if notification.Notify.MachineName != s.agent.machineName() || len(notification.Notify.PushTokens) != 1 ||
		notification.Notify.PushTokens[0] != pushToken {
		t.Fatalf("unexpected notification %+v", notification)
	}
	approval := s.phone.waitForApproval()
	s.phone.answer(actionDeny, approval, "")
	exitStatus(t, result)
}

func TestLoadApproversRejectsUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "approvers.json")
	os.WriteFile(path, []byte(`{"machineId":"m","machineName":"n","devices":[{"id":"d","name":"p","publicKey":""}]}`), 0o644)
	if _, err := loadApprovers(path); err != nil {
		t.Fatalf("safe file rejected: %v", err)
	}
	os.Chmod(path, 0o666)
	if _, err := loadApprovers(path); err == nil {
		t.Fatal("world-writable file accepted")
	}
	os.Chmod(path, 0o644)
	os.Chmod(dir, 0o777)
	if _, err := loadApprovers(path); err == nil {
		t.Fatal("file in a world-writable folder accepted")
	}
	os.Chmod(dir, 0o755)
	link := filepath.Join(dir, "link.json")
	os.Symlink(path, link)
	if _, err := loadApprovers(link); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestDescribeRequest(t *testing.T) {
	title, detail := describeRequest("sudo", "ruben", "/dev/ttys003", []string{"sudo", "pacman", "-S", "a b", "x\ny"})
	if title != `sudo pacman -S "a b" "x\ny"` || detail != "ruben on ttys003" {
		t.Fatalf("got %q / %q", title, detail)
	}
	if title, _ := describeRequest("polkit-1", "ruben", "", []string{"/usr/lib/polkit-1/polkit-agent-helper-1", "ruben"}); title != "Administrator access (system dialog)" {
		t.Fatalf("polkit: %q", title)
	}
	long, _ := describeRequest("sudo", "ruben", "", []string{"sudo", strings.Repeat("x", 500)})
	if n := len([]rune(long)); n != maxTitleLength || strings.ContainsAny(long, "\n\r") {
		t.Fatalf("long title has %d characters", n)
	}
	if got := oneLine("a\nb c", 10); got != "a b c" {
		t.Fatalf("oneLine: %q", got)
	}
}

func TestSudoWithoutPrompt(t *testing.T) {
	for args, want := range map[string]bool{
		"sudo pacman -Syu":            false,
		"sudo -S true":                true,
		"sudo -n true":                true,
		"sudo -kS true":               true,
		"sudo --stdin true":           true,
		"sudo --non-interactive true": true,
		"sudo -u nobody -S true":      true,
		"sudo -u nobody true":         false,
		"sudo -unobody true":          false,
		"sudo -u n true":              false,
		"sudo --user n true":          false,
		"sudo --user=n -n true":       true,
		"sudo ls -n":                  false,
		"sudo -- -S":                  false,
		"sudo -i":                     false,
	} {
		if got := sudoWithoutPrompt(strings.Fields(args)); got != want {
			t.Errorf("%s: got %v", args, got)
		}
	}
}

func TestPAMLines(t *testing.T) {
	line := "auth       sufficient   pam_exec.so quiet stdout seteuid " + checkerInstallPath + " pam"
	arch := "#%PAM-1.0\nauth\t\tinclude\t\tsystem-auth\naccount\t\tinclude\t\tsystem-auth\nsession\t\tinclude\t\tsystem-auth\n"
	debian := "#%PAM-1.0\n\nsession    required   pam_limits.so\n\n@include common-auth\n@include common-account\n"
	mac := "# sudo_local: local config file which survives system update and is included for sudo\nauth       sufficient     pam_tid.so\n"
	for name, config := range map[string]string{"arch": arch, "debian": debian, "mac": mac} {
		added := addPAMLine(config, line)
		lines := strings.Split(added, "\n")
		at := -1
		for i, l := range lines {
			if l == line {
				at = i
			}
		}
		next := lines[at+1]
		if at < 1 || lines[at-1] != pamMarker || !(strings.HasPrefix(next, "auth") || strings.HasPrefix(next, "@include common-auth")) {
			t.Fatalf("%s: line in the wrong place:\n%s", name, added)
		}
		if again := addPAMLine(added, line); again != added {
			t.Fatalf("%s: not idempotent:\n%s", name, again)
		}
		if removed := removePAMLines(added); removed != config {
			t.Fatalf("%s: removing didn't restore:\n%q\n%q", name, removed, config)
		}
	}
	fresh := addPAMLine("# sudo_local: header\n", "auth sufficient "+macModulePath)
	if fresh != "# sudo_local: header\n"+pamMarker+"\nauth sufficient "+macModulePath+"\n" {
		t.Fatalf("new sudo_local:\n%s", fresh)
	}
}

func TestVendorPAMOverride(t *testing.T) {
	// polkit on Arch and Debian ships only /usr/lib/pam.d/polkit-1; /etc/pam.d/polkit-1 overrides it.
	etc, vendor := t.TempDir(), t.TempDir()
	defer func(dir string, dirs []string) { pamDir, vendorPAMDirs = dir, dirs }(pamDir, vendorPAMDirs)
	pamDir, vendorPAMDirs = etc, []string{vendor}
	sudo := "#%PAM-1.0\nauth\t\tinclude\t\tsystem-auth\naccount\t\tinclude\t\tsystem-auth\n"
	polkit := "#%PAM-1.0\nauth       include      system-auth\naccount    include      system-auth\n"
	os.WriteFile(filepath.Join(etc, "sudo"), []byte(sudo), 0o644)
	os.WriteFile(filepath.Join(vendor, "polkit-1"), []byte(polkit), 0o644)

	line := "auth       sufficient   pam_exec.so quiet stdout seteuid " + checkerInstallPath + " pam"
	for range []int{1, 2} { // running enable-sudo twice must not stack anything
		if err := addLinuxPAMLines(line); err != nil {
			t.Fatal(err)
		}
	}
	override, err := os.ReadFile(filepath.Join(etc, "polkit-1"))
	if err != nil {
		t.Fatal("no polkit override created")
	}
	if !strings.HasPrefix(string(override), createdMarker) || strings.Count(string(override), line) != 1 ||
		!strings.Contains(string(override), line+"\nauth       include      system-auth") {
		t.Fatalf("override:\n%s", override)
	}
	if _, err := os.Stat(filepath.Join(etc, "polkit-1.before-"+appID)); err == nil {
		t.Fatal("backed up a file it created")
	}

	files := []string{filepath.Join(etc, "sudo"), filepath.Join(etc, "polkit-1")}
	if err := removePAMConfig(files); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(etc, "polkit-1")); err == nil {
		t.Fatal("override not removed")
	}
	if restored, _ := os.ReadFile(filepath.Join(etc, "sudo")); string(restored) != sudo {
		t.Fatalf("sudo not restored:\n%q", restored)
	}
	if left, _ := os.ReadFile(filepath.Join(vendor, "polkit-1")); string(left) != polkit {
		t.Fatal("vendor file changed")
	}
}

func TestWithoutEmulator(t *testing.T) {
	rosetta := []string{"/run/rosetta/rosetta", "/usr/sbin/sudo", "sudo", "-k", "-S", "id"}
	args := withoutEmulator(rosetta)
	if !sudoWithoutPrompt(args) {
		t.Fatalf("-S not seen in %q", args)
	}
	if title, _ := describeRequest("sudo", "ruben", "", args); title != "sudo -k -S id" {
		t.Fatalf("title %q", title)
	}
	if got := withoutEmulator([]string{"sudo", "id"}); len(got) != 2 {
		t.Fatalf("native args changed: %q", got)
	}
}

func TestParentOf(t *testing.T) {
	parent, name, err := parentOf(os.Getpid())
	if err != nil || parent != os.Getppid() || name == "" {
		t.Fatalf("parentOf: %d %q %v", parent, name, err)
	}
}

// TestCheckerExitsWithParent: when sudo is killed, the checker must stop too, so the request disappears.
func TestCheckerExitsWithParent(t *testing.T) {
	if os.Getenv(envPrefix+"TEST_ORPHAN") == "1" {
		exitWithParent(os.Getppid(), nil)
		return
	}
	shell := exec.Command("sh", "-c", `"$0" -test.run='^TestCheckerExitsWithParent$' & echo $!; wait`, os.Args[0])
	shell.Env = append(os.Environ(), envPrefix+"TEST_ORPHAN=1")
	out, _ := shell.StdoutPipe()
	if err := shell.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(out).ReadString('\n')
	child, _ := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || child == 0 {
		t.Fatalf("no child pid: %q %v", line, err)
	}
	time.Sleep(300 * time.Millisecond)
	shell.Process.Kill()
	shell.Wait()
	waitUntil(t, func() bool { return syscall.Kill(child, 0) != nil })
}
