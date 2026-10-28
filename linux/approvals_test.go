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
	// The checker's parent here is the test runner, not sudo.
	t.Cleanup(func() { requesterInfo = processInfo })
	requesterInfo = func(int) ([]string, map[string]string, error) {
		return []string{"sudo", "id"}, map[string]string{"PATH": "/usr/bin:/bin"}, nil
	}
	t.Setenv("PAM_TTY", "/dev/pts/7")
	t.Setenv("PAM_TYPE", "auth")
	return setup
}

// writeApprovers saves approvers.json as enable-sudo does, with the device ids hashed.
func (s *approvalSetup) writeApprovers(t *testing.T, approvers *Approvers) {
	data, _ := json.Marshal(approvers.hashed())
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
	s.agent.state.ApprovalWait = 1
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
	title, detail, _ := describeRequest("sudo", "ruben", "/dev/ttys003", []string{"sudo", "pacman", "-S", "a b", "x\ny"})
	if title != `sudo pacman -S "a b" "x\ny"` || detail != "ruben on ttys003" {
		t.Fatalf("got %q / %q", title, detail)
	}
	if title, _, _ := describeRequest("polkit-1", "ruben", "", []string{"/usr/lib/polkit-1/polkit-agent-helper-1", "ruben"}); title != polkitTitle {
		t.Fatalf("polkit: %q", title)
	}
	// Invisible characters could make the iPhone show something else than what runs, so they're escaped:
	// a right-to-left override, a zero-width space and a no-break space that looks like a word break.
	sneaky, _, _ := describeRequest("sudo", "ruben", "", []string{"sudo", "rm", "safe\u202etxt.sh", "a\u200bb", "x\u00a0y", "café"})
	if sneaky != `sudo rm "safe\u202etxt.sh" "a\u200bb" "x\u00a0y" café` {
		t.Fatalf("got %q", sneaky)
	}
	fits := "sudo " + strings.Repeat("x", maxTitleLength-len("sudo "))
	if title, _, err := describeRequest("sudo", "ruben", "", strings.Fields(fits)); err != nil || title != fits {
		t.Fatalf("a title of exactly %d characters: %q, %v", maxTitleLength, title, err)
	}
	if _, _, err := describeRequest("sudo", "ruben", "", []string{"sudo", strings.Repeat("x", 500)}); err != errTitleTooLong {
		t.Fatalf("a command too long to show in full: %v", err)
	}
	// A first argument that isn't sudo (an empty one shifts what procargs shows) gets the password prompt, and so
	// does a command that couldn't be read.
	for _, args := range [][]string{{"/tmp/evil", "pacman", "-Syu"}, {"", "x"}, nil} {
		if _, _, err := describeRequest("sudo", "ruben", "", args); err != errUnknownCommand {
			t.Fatalf("%q: %v", args, err)
		}
	}
	if title, _, _ := describeRequest("sudo", "ruben", "", []string{"/usr/bin/sudoedit", "/etc/hosts"}); title != "sudoedit /etc/hosts" {
		t.Fatalf("sudoedit: %q", title)
	}
	// Invalid UTF-8 and the replacement character would show as a space, splitting one argument in two.
	if title, _, _ := describeRequest("sudo", "ruben", "", []string{"sudo", "cp", "a\xffb", "a\ufffdb", "/etc/x"}); title != `sudo cp "a\xffb" "a\ufffdb" /etc/x` {
		t.Fatalf("invalid UTF-8: %q", title)
	}
	// Letters and symbols that look blank: the Braille blank, a Hangul filler, the combining grapheme joiner.
	if title, _, _ := describeRequest("sudo", "ruben", "", []string{"sudo", "ls\u2800-la", "a\u3164b", "c\u034fd"}); title != `sudo "ls\u2800-la" "a\u3164b" "c\u034fd"` {
		t.Fatalf("blank-looking characters: %q", title)
	}
	if title, _, _ := describeRequest("sudo", "ruben", "", []string{"sudo", "k\U000E0100l"}); title != `sudo "k\U000e0100l"` {
		t.Fatalf("a variation selector above U+FFFF: %q", title)
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

// Emulated sudo gets the password prompt: its arguments read differently depending on who reads them. It goes by the
// program the process runs; whoever starts sudo picks its first argument, so a name like an emulator's changes nothing.
func TestUnderEmulator(t *testing.T) {
	for executable, want := range map[string]bool{"/run/rosetta/rosetta": true, "/usr/bin/qemu-x86_64": true, "/usr/bin/sudo": false} {
		if underEmulator(executable) != want {
			t.Errorf("%s", executable)
		}
	}
	if _, _, err := describeRequest("sudo", "ruben", "", []string{"qemu-x", "/tmp/evil", "x", "pacman", "-Syu"}); err != errUnknownCommand {
		t.Fatalf("qemu-named first argument: %v", err)
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

func TestDescribeApproverChanges(t *testing.T) {
	phone := Approver{ID: "a", Name: "Ruben's iPhone", PublicKey: []byte{1}}
	old := Approver{ID: "b", Name: "Old iPhone", PublicKey: []byte{2}}
	previous := (&Approvers{MachineName: "omarchy", Devices: []Approver{phone, old}}).hashed() // as approvers.json has it

	// A second "Ruben's iPhone" is new; so is a known id with another key.
	impostor := Approver{ID: "c", Name: "Ruben's iPhone", PublicKey: []byte{3}}
	swapped := Approver{ID: "a", Name: "Ruben's iPhone", PublicKey: []byte{4}}
	got := describeApproverChanges(previous, &Approvers{MachineName: "omarchy", Devices: []Approver{phone, impostor}})
	key := func(device Approver) string { return ", key " + keyFingerprint(device.PublicKey) }
	want := "These iPhones will approve sudo on omarchy:\n  Ruben's iPhone" + key(phone) + "\n  Ruben's iPhone" + key(impostor) + "  (new)\nNo longer: Old iPhone\n"
	if got != want {
		t.Fatalf("got\n%s", got)
	}
	if got := describeApproverChanges(previous, &Approvers{MachineName: "omarchy", Devices: []Approver{swapped}}); !strings.Contains(got, "Ruben's iPhone"+key(swapped)+"  (new)") {
		t.Fatalf("a new key for a known iPhone isn't marked:\n%s", got)
	}
	pairedAt := time.Date(2026, 10, 28, 12, 0, 0, 0, time.Local)
	dated := Approver{ID: "d", Name: "iPhone", PublicKey: []byte("test"), PairedAt: &pairedAt}
	if got := describeApprover(dated); got != "iPhone, key 9F86-D081-884C, paired 28 Oct 2026" {
		t.Fatalf("describeApprover: %q", got)
	}
	// The first setup has nothing to compare with.
	if got := describeApproverChanges(nil, &Approvers{MachineName: "omarchy", Devices: []Approver{phone}}); strings.Contains(got, "new") {
		t.Fatalf("first setup:\n%s", got)
	}
}

// An update finds the line already in sudo_local and leaves the file alone: macOS protects /etc/pam.d, and the Mac
// app's administrator prompt can't change it.
func TestAddPAMLineKeepsAFileThatHasIt(t *testing.T) {
	line := "auth       sufficient     " + macModulePath + " " + checkerInstallPath
	set := "# sudo_local: local config file which survives system update and is included for sudo\n" + pamMarker + "\n" + line + "\n"
	if got := addPAMLine(set, line); got != set {
		t.Fatalf("changed a file that already has the line:\n%q\n%q", set, got)
	}
	if fresh := "# sudo_local: local config file which survives system update and is included for sudo\n"; addPAMLine(fresh, line) == fresh {
		t.Fatal("didn't add the line")
	}
	// enableMacPAM leaves the line where you put it, such as below pam_tid.so, instead of moving it up (which the
	// administrator prompt can't).
	below := "auth       sufficient     pam_tid.so\n" + pamMarker + "\n" + line + "\n"
	if !hasPAMLine(below, "auth sufficient "+macModulePath+" "+checkerInstallPath) || hasPAMLine(below, "auth sufficient pam_tid.so.2") {
		t.Fatal("hasPAMLine")
	}
}

// approvers.json is readable by everyone, and a device id is all a hello needs, so it only keeps their hashes.
func TestApproversFileKeepsOnlyHashes(t *testing.T) {
	if got := deviceIDHash("abc"); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("deviceIDHash: %s", got)
	}
	approvers := &Approvers{MachineID: "m", MachineName: "n", Devices: []Approver{{ID: "device-1", Name: "iPhone"}}}
	data, _ := json.Marshal(approvers.hashed())
	if strings.Contains(string(data), "device-1") || approvers.Devices[0].ID != "device-1" {
		t.Fatalf("hashed: %s", data)
	}
	var saved Approvers
	json.Unmarshal(data, &saved)
	// Found by the id itself, in the new file and in one from before 1.0.3.
	for _, list := range []*Approvers{&saved, approvers} {
		if list.find("device-1") == nil || list.find("device-2") != nil || list.find("") != nil {
			t.Fatalf("find in %+v", list.Devices)
		}
	}
}

func TestCheckSudoProgram(t *testing.T) {
	root := t.TempDir()
	safe, open := filepath.Join(root, "bin"), filepath.Join(root, "open")
	os.Mkdir(safe, 0o755)
	os.Mkdir(open, 0o755)
	os.Chmod(open, 0o777) // anyone can swap what's in it
	for _, dir := range []string{safe, open} {
		os.WriteFile(filepath.Join(dir, "tool"), []byte("#!/bin/sh\n"), 0o755)
	}
	os.WriteFile(filepath.Join(safe, "loose"), []byte("#!/bin/sh\n"), 0o755)
	os.Chmod(filepath.Join(safe, "loose"), 0o777)
	os.WriteFile(filepath.Join(safe, "data"), nil, 0o644)
	os.Symlink(filepath.Join(open, "tool"), filepath.Join(safe, "linked"))
	os.Symlink("tool", filepath.Join(safe, "alias"))

	env := map[string]string{"PATH": safe, "SHELL": filepath.Join(safe, "tool")}
	for args, want := range map[string]bool{
		"sudo tool":                    true,
		"sudo -u nobody tool -x":       true,
		"sudo FOO=bar tool":            true,
		"sudo -- tool":                 true,
		"sudo alias":                   true, // a link next to it, in the same safe folder
		"sudo " + safe + "/tool":       true,
		"sudo --preserve-env=FOO tool": true,
		"sudo -i":                      true,
		"sudo -v":                      true,
		"sudo -s":                      true,
		"sudoedit /etc/hosts":          true,
		"sudo -e /etc/hosts":           true,
		"sudo " + open + "/tool":       false, // in a folder anyone can write to
		"sudo loose":                   false, // writable by anyone
		"sudo linked":                  false, // a link into the open folder
		"sudo data":                    false, // not a program, so sudo wouldn't find it
		"sudo missing":                 false,
		"sudo ./tool":                  false,
		"sudo -E tool":                 false,
		"sudo --preserve-env tool":     false,
		"sudo -Eu nobody tool":         false,
	} {
		if err := checkSudoProgram(strings.Fields(args), env); (err == nil) != want {
			t.Errorf("%s: %v", args, err)
		}
	}
	// The first match in PATH is the one sudo runs: one in a folder others can write to comes first.
	if err := checkSudoProgram([]string{"sudo", "tool"}, map[string]string{"PATH": open + ":" + safe}); err == nil ||
		!strings.Contains(err.Error(), open) {
		t.Errorf("open folder first: %v", err)
	}
	for _, path := range []string{"", ".:" + safe, "bin:" + safe} {
		env := map[string]string{"PATH": path}
		if path == "" {
			delete(env, "PATH")
		}
		if err := checkSudoProgram([]string{"sudo", "tool"}, env); err == nil {
			t.Errorf("PATH %q accepted", path)
		}
	}
	if err := checkSudoProgram([]string{"sudo", "-s"}, map[string]string{"SHELL": open + "/tool"}); err == nil {
		t.Error("a shell others can change accepted")
	}
	// sudo -s runs SHELL, so an environment the checker couldn't read (nil) isn't enough; one without SHELL is.
	if checkSudoProgram([]string{"sudo", "-s"}, nil) == nil || checkSudoProgram([]string{"sudo", "-s"}, map[string]string{}) != nil {
		t.Error("sudo -s without SHELL")
	}
	// Links on the way count like the program: one in a safe folder to a safe folder, but not one in a folder others
	// can write to.
	os.Symlink(safe, filepath.Join(safe, "here"))
	os.Symlink(safe, filepath.Join(open, "there"))
	for path, want := range map[string]bool{safe + "/here/tool": true, safe + "/here/../bin/tool": true, open + "/there/tool": false, safe: false} {
		if err := checkProgram(path); (err == nil) != want {
			t.Errorf("%s: %v", path, err)
		}
	}
	if os.Geteuid() == 0 {
		// In a sticky folder others can't swap root's entries, but they can swap their own links.
		sticky := filepath.Join(root, "sticky")
		os.Mkdir(sticky, 0o755)
		os.Chmod(sticky, 0o777|os.ModeSticky)
		os.Symlink(filepath.Join(safe, "tool"), filepath.Join(sticky, "root-link"))
		os.Symlink(filepath.Join(safe, "tool"), filepath.Join(sticky, "their-link"))
		os.Lchown(filepath.Join(sticky, "their-link"), 65534, 65534)
		if checkProgram(filepath.Join(sticky, "root-link")) != nil || checkProgram(filepath.Join(sticky, "their-link")) == nil {
			t.Error("links in a sticky folder")
		}
	}
	// What a real system has: root's own programs.
	if err := checkSudoProgram([]string{"sudo", "id"}, map[string]string{"PATH": "/usr/bin:/bin"}); err != nil {
		t.Errorf("id: %v", err)
	}
}

// Debian's `sudo -i` has its own PAM config, sudo-i; a system without it (or without polkit) is left as it is.
func TestLinuxPAMServices(t *testing.T) {
	dir := t.TempDir()
	defer func(dir string, vendor []string) { pamDir, vendorPAMDirs = dir, vendor }(pamDir, vendorPAMDirs)
	pamDir, vendorPAMDirs = dir, []string{filepath.Join(dir, "vendor")}
	for _, service := range []string{"sudo", "sudo-i"} {
		os.WriteFile(filepath.Join(dir, service), []byte("#%PAM-1.0\n@include common-auth\n"), 0o644)
	}
	line := "auth sufficient pam_exec.so " + checkerInstallPath
	if err := addLinuxPAMLines(line); err != nil {
		t.Fatal(err)
	}
	for _, service := range []string{"sudo", "sudo-i"} {
		if data, _ := os.ReadFile(filepath.Join(dir, service)); !strings.Contains(string(data), line) {
			t.Errorf("%s:\n%s", service, data)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "polkit-1")); err == nil {
		t.Error("made a polkit-1 config without polkit")
	}
}
