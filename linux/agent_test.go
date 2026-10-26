package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

type memoryPasswords struct {
	password string
	check    passwordCheck
}

func (m *memoryPasswords) Load() (string, error) {
	if m.password == "" {
		return "", errNoPassword
	}
	return m.password, nil
}
func (m *memoryPasswords) Save(p string) error        { m.password = p; return nil }
func (m *memoryPasswords) Clear() error               { m.password = ""; return nil }
func (m *memoryPasswords) Check(string) passwordCheck { return m.check }

// passwordScreen is a fake lock screen that, like Omarchy's, needs the password typed.
type passwordScreen struct {
	fakeScreen
	typed string
}

func (s *passwordScreen) NeedsPassword() bool { return true }
func (s *passwordScreen) Unlock(password string) error {
	s.typed = password
	return s.fakeScreen.Unlock(password)
}

// phone stands in for the iPhone app. Without a passwordKey it's an app from before sealed passwords.
type phone struct {
	t           *testing.T
	agent       *Agent
	key         *ecdsa.PrivateKey
	deviceID    string
	passwordKey *ecdh.PrivateKey
}

func newTestAgent(t *testing.T, screen Screen, passwords PasswordStore) *Agent {
	t.Setenv(envPrefix+"CONFIG_DIR", t.TempDir())
	state, err := loadState()
	if err != nil {
		t.Fatal(err)
	}
	return newAgent(state, screen, passwords)
}

func (p *phone) call(path string, request any) (int, map[string]any) {
	body, _ := json.Marshal(request)
	status, result := p.agent.handle(path, body)
	data, _ := json.Marshal(result)
	var decoded map[string]any
	json.Unmarshal(data, &decoded)
	return status, decoded
}

func (p *phone) pair(token string) (int, map[string]any) {
	publicKey := base64.StdEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), p.key.X, p.key.Y))
	passwordKey := ""
	if p.passwordKey != nil {
		passwordKey = b64(p.passwordKey.PublicKey().Bytes())
	}
	proof := base64.StdEncoding.EncodeToString(pairingProof(token, p.agent.state.MachineID, p.deviceID, "Test iPhone", publicKey, passwordKey))
	return p.call("/v1/pair", PairRequest{DeviceID: p.deviceID, DeviceName: "Test iPhone", PublicKey: publicKey, Proof: proof,
		PasswordKey: passwordKey})
}

func (p *phone) sign(action Action, nonce string) string {
	return p.signMessage(signedMessage(p.agent.state.MachineID, p.deviceID, action, nonce))
}

func (p *phone) signMessage(message []byte) string {
	digest := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, p.key, digest[:])
	if err != nil {
		p.t.Fatal(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	return base64.StdEncoding.EncodeToString(raw)
}

func (p *phone) send(action Action) (int, map[string]any) {
	status, hello := p.call("/v1/hello", HelloRequest{DeviceID: p.deviceID})
	if status != 200 {
		return status, hello
	}
	nonce := hello["nonce"].(string)
	return p.call("/v1/command", CommandRequest{DeviceID: p.deviceID, Action: action, Nonce: nonce, Signature: p.sign(action, nonce)})
}

// command builds a command the way the current app does: it registers its password key when hello asks, and for an
// unlock wraps the sealed password's key to the challenge's session key. sessionKey overrides the one it encrypts
// to, as a relay that swapped it would.
func (p *phone) command(action Action, hello map[string]any, sessionKey string) CommandRequest {
	nonce := hello["nonce"].(string)
	request := CommandRequest{DeviceID: p.deviceID, Action: action, Nonce: nonce}
	if hello["wantsPasswordKey"] == true {
		if p.passwordKey == nil {
			p.passwordKey, _ = ecdh.P256().GenerateKey(rand.Reader)
		}
		request.PasswordKey = b64(p.passwordKey.PublicKey().Bytes())
	}
	if challenge, ok := hello["sealedPassword"].(map[string]any); ok && action == actionUnlock {
		if sessionKey == "" {
			sessionKey = challenge["sessionKey"].(string)
		}
		wrapped := p.wrap(challenge["sealKey"].(string), sessionKey, nonce)
		request.WrappedKey = &wrapped
	}
	if !request.carriesPasswordKeys() {
		request.Signature = p.sign(action, nonce)
		return request
	}
	signedSession := ""
	if challenge, ok := hello["sealedPassword"].(map[string]any); ok {
		signedSession = challenge["sessionKey"].(string)
	}
	if sessionKey != "" {
		signedSession = sessionKey
	}
	request.Signature = p.signMessage(signedMessageV2(p.agent.state.MachineID, p.deviceID, action, nonce, signedSession,
		request.PasswordKey, request.WrappedKey))
	return request
}

// wrap does the iPhone's part of opening a sealed password (PasswordSeal.swift).
func (p *phone) wrap(sealKey, sessionKey, nonce string) WrappedKey {
	sealBytes, _ := base64.StdEncoding.DecodeString(sealKey)
	sealPublic, err := ecdh.P256().NewPublicKey(sealBytes)
	if err != nil {
		p.t.Fatal(err)
	}
	shared, err := p.passwordKey.ECDH(sealPublic)
	if err != nil {
		p.t.Fatal(err)
	}
	key := hkdfSHA256(shared, sealBytes, sealInfo(p.agent.state.MachineID, p.deviceID))
	sessionBytes, _ := base64.StdEncoding.DecodeString(sessionKey)
	session, err := ecdh.P256().NewPublicKey(sessionBytes)
	if err != nil {
		p.t.Fatal(err)
	}
	ephemeral, _ := ecdh.P256().GenerateKey(rand.Reader)
	wrappingSecret, _ := ephemeral.ECDH(session)
	nonceBytes := make([]byte, 12)
	rand.Read(nonceBytes)
	box, err := gcmSeal(hkdfSHA256(wrappingSecret, ephemeral.PublicKey().Bytes(), wrapInfo(p.agent.state.MachineID, p.deviceID, nonce)),
		nonceBytes, key)
	if err != nil {
		p.t.Fatal(err)
	}
	return WrappedKey{Key: b64(ephemeral.PublicKey().Bytes()), Box: b64(box)}
}

// sendCurrent sends action as the current app does.
func (p *phone) sendCurrent(action Action) (int, map[string]any) {
	status, hello := p.call("/v1/hello", HelloRequest{DeviceID: p.deviceID})
	if status != 200 {
		return status, hello
	}
	return p.call("/v1/command", p.command(action, hello, ""))
}

func newPhone(t *testing.T, agent *Agent) *phone {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &phone{t: t, agent: agent, key: key, deviceID: randomUUID()}
}

func TestPairUnlockLock(t *testing.T) {
	screen := &passwordScreen{}
	passwords := &memoryPasswords{password: "hunter2", check: checkCorrect}
	agent := newTestAgent(t, screen, passwords)
	phone := newPhone(t, agent)

	if status, _ := phone.pair("wrong"); status != 403 {
		t.Fatalf("pairing without an active code: got %d", status)
	}
	token, _ := agent.auth.StartPairing()
	if status, body := phone.pair(token); status != 200 || body["machineId"] != agent.state.MachineID {
		t.Fatalf("pairing failed: %d %v", status, body)
	}
	if reloaded, _ := loadState(); len(reloaded.Devices) != 1 {
		t.Fatal("pairing wasn't saved")
	}

	if status, body := phone.send(actionLock); status != 200 || body["ok"] != true || body["locked"] != true {
		t.Fatalf("lock failed: %d %v", status, body)
	}
	if status, body := phone.send(actionUnlock); status != 200 || body["ok"] != true || body["locked"] != false {
		t.Fatalf("unlock failed: %d %v", status, body)
	}
	if screen.typed != "hunter2" {
		t.Fatalf("typed %q", screen.typed)
	}
	if status, body := phone.send(actionUnlock); status != 200 || body["message"] != "Already unlocked" {
		t.Fatalf("second unlock: %d %v", status, body)
	}
}

func TestUnlockRefusesWrongOrMissingPassword(t *testing.T) {
	screen := &passwordScreen{}
	passwords := &memoryPasswords{password: "old", check: checkWrong}
	agent := newTestAgent(t, screen, passwords)
	phone := newPhone(t, agent)
	token, _ := agent.auth.StartPairing()
	phone.pair(token)
	screen.Lock()

	if status, _ := phone.send(actionUnlock); status != 409 || screen.typed != "" {
		t.Fatalf("wrong password: got %d, typed %q", status, screen.typed)
	}
	passwords.password = ""
	if status, _ := phone.send(actionUnlock); status != 409 {
		t.Fatalf("missing password: got %d", status)
	}
}

func TestReplayAndForgeryRejected(t *testing.T) {
	agent := newTestAgent(t, &fakeScreen{}, &memoryPasswords{})
	phone := newPhone(t, agent)
	token, _ := agent.auth.StartPairing()
	phone.pair(token)

	_, hello := phone.call("/v1/hello", HelloRequest{DeviceID: phone.deviceID})
	nonce := hello["nonce"].(string)
	request := CommandRequest{DeviceID: phone.deviceID, Action: actionStatus, Nonce: nonce, Signature: phone.sign(actionStatus, nonce)}
	if status, _ := phone.call("/v1/command", request); status != 200 {
		t.Fatalf("first use: %d", status)
	}
	if status, _ := phone.call("/v1/command", request); status != 403 {
		t.Fatalf("replay accepted: %d", status)
	}

	_, hello = phone.call("/v1/hello", HelloRequest{DeviceID: phone.deviceID})
	nonce = hello["nonce"].(string)
	forged := CommandRequest{DeviceID: phone.deviceID, Action: actionUnlock, Nonce: nonce, Signature: phone.sign(actionStatus, nonce)}
	if status, _ := phone.call("/v1/command", forged); status != 403 {
		t.Fatalf("signature for another action accepted: %d", status)
	}

	stranger := newPhone(t, agent)
	if status, _ := stranger.call("/v1/hello", HelloRequest{DeviceID: stranger.deviceID}); status != 403 {
		t.Fatalf("unknown device got a nonce: %d", status)
	}
}

func TestNonceExpires(t *testing.T) {
	agent := newTestAgent(t, &fakeScreen{}, &memoryPasswords{})
	now := time.Now()
	agent.auth.now = func() time.Time { return now }
	phone := newPhone(t, agent)
	token, _ := agent.auth.StartPairing()
	phone.pair(token)

	_, hello := phone.call("/v1/hello", HelloRequest{DeviceID: phone.deviceID})
	nonce := hello["nonce"].(string)
	now = now.Add(nonceLifetime + time.Second)
	request := CommandRequest{DeviceID: phone.deviceID, Action: actionStatus, Nonce: nonce, Signature: phone.sign(actionStatus, nonce)}
	if status, body := phone.call("/v1/command", request); status != 403 || body["error"] != string(errExpiredNonce) {
		t.Fatalf("expired nonce: %d %v", status, body)
	}
}

func newCurrentPhone(t *testing.T, agent *Agent) *phone {
	phone := newPhone(t, agent)
	phone.passwordKey, _ = ecdh.P256().GenerateKey(rand.Reader)
	return phone
}

func TestSealedPasswordUnlocks(t *testing.T) {
	screen := &passwordScreen{}
	passwords := &memoryPasswords{check: checkCorrect}
	agent := newTestAgent(t, screen, passwords)
	phone := newCurrentPhone(t, agent)
	token, _ := agent.auth.StartPairing()
	if status, body := phone.pair(token); status != 200 {
		t.Fatalf("pairing failed: %d %v", status, body)
	}
	if message, err := agent.setPassword("hunter2"); err != nil || !strings.Contains(message, "encrypted") {
		t.Fatalf("set-password: %q %v", message, err)
	}
	if data, _ := os.ReadFile(statePath()); strings.Contains(string(data), "hunter2") || !strings.Contains(string(data), "sealedPasswords") {
		t.Fatalf("state file: %s", data)
	}
	// The plain copy stays until the iPhone has shown that its password key opens the sealed copy.
	if passwords.password != "hunter2" {
		t.Fatal("the plain copy went before the iPhone opened its sealed copy")
	}

	screen.Lock()
	sealKey := b64(agent.state.SealedPasswords[phone.deviceID].Key)
	if status, body := phone.sendCurrent(actionUnlock); status != 200 || body["ok"] != true || screen.typed != "hunter2" {
		t.Fatalf("unlock: %d %v, typed %q", status, body, screen.typed)
	}
	if passwords.password != "" {
		t.Fatal("the plain copy stayed after the iPhone opened its sealed copy")
	}
	// Sealed again under a fresh key, so the key that just left the iPhone can't open it any more.
	if b64(agent.state.SealedPasswords[phone.deviceID].Key) == sealKey {
		t.Fatal("not sealed again after the unlock")
	}

	// An app from before sealed passwords can't open it.
	screen.Lock()
	screen.typed = ""
	if status, body := phone.send(actionUnlock); status != 409 || !strings.Contains(body["error"].(string), "Update") || screen.typed != "" {
		t.Fatalf("unlock without the wrapped key: %d %v", status, body)
	}

	// A relay that swaps the session key in hello gets a key it can use, but the agent rejects the signature.
	_, hello := phone.call("/v1/hello", HelloRequest{DeviceID: phone.deviceID})
	attacker, _ := ecdh.P256().GenerateKey(rand.Reader)
	request := phone.command(actionUnlock, hello, b64(attacker.PublicKey().Bytes()))
	if status, _ := phone.call("/v1/command", request); status != 403 || screen.typed != "" {
		t.Fatalf("swapped session key: %d, typed %q", status, screen.typed)
	}

	// A key wrapped for another challenge doesn't open it, even when signed correctly.
	_, first := phone.call("/v1/hello", HelloRequest{DeviceID: phone.deviceID})
	_, second := phone.call("/v1/hello", HelloRequest{DeviceID: phone.deviceID})
	stale := phone.command(actionUnlock, first, "")
	request = phone.command(actionUnlock, second, "")
	request.WrappedKey = stale.WrappedKey
	request.Signature = phone.signMessage(signedMessageV2(agent.state.MachineID, phone.deviceID, actionUnlock, request.Nonce,
		second["sealedPassword"].(map[string]any)["sessionKey"].(string), "", request.WrappedKey))
	if status, _ := phone.call("/v1/command", request); status != 409 || screen.typed != "" {
		t.Fatalf("key from another challenge: %d, typed %q", status, screen.typed)
	}
}

func TestOlderAppMovesToSealedPassword(t *testing.T) {
	screen := &passwordScreen{}
	passwords := &memoryPasswords{password: "hunter2", check: checkCorrect}
	agent := newTestAgent(t, screen, passwords)
	phone := newPhone(t, agent)
	token, _ := agent.auth.StartPairing()
	phone.pair(token)

	screen.Lock()
	if status, body := phone.send(actionUnlock); status != 200 || screen.typed != "hunter2" {
		t.Fatalf("older app unlock: %d %v", status, body)
	}

	// After an update the app registers its password key with its next command; the agent seals the keyring's
	// password to it and then removes the plain copy.
	screen.Lock()
	if status, body := phone.sendCurrent(actionUnlock); status != 200 || body["ok"] != true {
		t.Fatalf("first unlock after the update: %d %v", status, body)
	}
	if _, sealed := agent.state.SealedPasswords[phone.deviceID]; !sealed || passwords.password != "hunter2" {
		t.Fatalf("after registering: sealed %v, keyring %q", sealed, passwords.password)
	}
	screen.Lock()
	screen.typed = ""
	if status, body := phone.sendCurrent(actionUnlock); status != 200 || screen.typed != "hunter2" {
		t.Fatalf("sealed unlock: %d %v, typed %q", status, body, screen.typed)
	}
	if passwords.password != "" {
		t.Fatalf("keyring still has %q after a sealed unlock", passwords.password)
	}
}

func TestKeyringCopyStaysForOlderApps(t *testing.T) {
	screen := &passwordScreen{}
	passwords := &memoryPasswords{check: checkCorrect}
	agent := newTestAgent(t, screen, passwords)

	// Saved before pairing: it waits in the keyring and is sealed to the iPhone as it pairs.
	if message, _ := agent.setPassword("hunter2"); !strings.Contains(message, "keyring") || passwords.password != "hunter2" {
		t.Fatalf("before pairing: %q, keyring %q", message, passwords.password)
	}
	current := newCurrentPhone(t, agent)
	token, _ := agent.auth.StartPairing()
	current.pair(token)
	agent.background.Wait()
	if _, sealed := agent.state.SealedPasswords[current.deviceID]; !sealed || passwords.password != "hunter2" {
		t.Fatalf("after pairing: sealed %v, keyring %q", sealed, passwords.password)
	}

	older := newPhone(t, agent)
	token, _ = agent.auth.StartPairing()
	older.pair(token)
	message, err := agent.setPassword("hunter2")
	if err != nil || !strings.Contains(message, "Test iPhone") || passwords.password != "hunter2" {
		t.Fatalf("with an older app paired: %q %v, keyring %q", message, err, passwords.password)
	}
	screen.Lock()
	if status, _ := older.send(actionUnlock); status != 200 || screen.typed != "hunter2" {
		t.Fatalf("older app: %d", status)
	}
	screen.Lock()
	screen.typed = ""
	if status, _ := current.sendCurrent(actionUnlock); status != 200 || screen.typed != "hunter2" {
		t.Fatalf("current app: %d", status)
	}

	// Removing the older app's pairing leaves only iPhones that open their sealed copies, so the plain one goes.
	if _, err := agent.unpair(older.deviceID); err != nil {
		t.Fatal(err)
	}
	if passwords.password != "" {
		t.Fatalf("keyring still has %q", passwords.password)
	}

	if err := agent.forgetPassword(); err != nil || len(agent.state.SealedPasswords) != 0 {
		t.Fatalf("forget: %v %v", err, agent.state.SealedPasswords)
	}
}

func TestNoPasswordKeyWithoutPasswordScreen(t *testing.T) {
	// hyprlock and logind unlock without the password, so there's nothing to seal.
	agent := newTestAgent(t, &fakeScreen{}, &memoryPasswords{})
	phone := newPhone(t, agent)
	token, _ := agent.auth.StartPairing()
	phone.pair(token)
	if _, hello := phone.call("/v1/hello", HelloRequest{DeviceID: phone.deviceID}); hello["wantsPasswordKey"] != nil {
		t.Fatalf("asked for a password key: %v", hello)
	}
	if status, body := phone.sendCurrent(actionLock); status != 200 || body["ok"] != true {
		t.Fatalf("lock: %d %v", status, body)
	}
}

// pausedScreen holds an unlock halfway, so a test can do something in the meantime.
type pausedScreen struct {
	passwordScreen
	entered chan struct{}
	resume  chan struct{}
}

func (s *pausedScreen) Unlock(password string) error {
	close(s.entered)
	<-s.resume
	return s.passwordScreen.Unlock(password)
}

func TestForgetDuringUnlockStaysForgotten(t *testing.T) {
	screen := &pausedScreen{entered: make(chan struct{}), resume: make(chan struct{})}
	agent := newTestAgent(t, screen, &memoryPasswords{check: checkCorrect})
	phone := newCurrentPhone(t, agent)
	token, _ := agent.auth.StartPairing()
	phone.pair(token)
	if _, err := agent.setPassword("hunter2"); err != nil {
		t.Fatal(err)
	}
	screen.Lock()
	_, hello := phone.call("/v1/hello", HelloRequest{DeviceID: phone.deviceID})
	body, _ := json.Marshal(phone.command(actionUnlock, hello, ""))
	done := make(chan struct{})
	go func() {
		agent.handle("/v1/command", body)
		close(done)
	}()
	<-screen.entered
	if err := agent.forgetPassword(); err != nil {
		t.Fatal(err)
	}
	close(screen.resume)
	<-done
	if saved, _ := loadState(); len(saved.SealedPasswords) != 0 {
		t.Fatal("the unlock that was under way sealed the forgotten password again")
	}
}

func TestPlainCopyStaysUntilSealedCopiesAreSaved(t *testing.T) {
	passwords := &memoryPasswords{check: checkCorrect}
	agent := newTestAgent(t, &passwordScreen{}, passwords)
	phone := newCurrentPhone(t, agent)
	token, _ := agent.auth.StartPairing()
	phone.pair(token)
	agent.background.Wait()
	agent.state.Devices[0].OpenedSealed = true
	passwords.password = "hunter2"
	// A directory where save writes its temp file makes every save fail.
	if err := os.Mkdir(statePath()+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		agent.passwordMu.Lock()
		agent.sealMissing("hunter2", agent.passwordGeneration)
		agent.passwordMu.Unlock()
		if passwords.password == "" {
			t.Fatalf("attempt %d removed the plain password without a sealed copy on disk", i+1)
		}
	}
}

// hookedPasswords runs a hook the first time the keyring is read or cleared.
type hookedPasswords struct {
	memoryPasswords
	onLoad, onClear func()
}

func (p *hookedPasswords) Load() (string, error) {
	if hook := p.onLoad; hook != nil {
		p.onLoad = nil
		hook()
	}
	return p.memoryPasswords.Load()
}

func (p *hookedPasswords) Clear() error {
	if hook := p.onClear; hook != nil {
		p.onClear = nil
		hook()
	}
	return p.memoryPasswords.Clear()
}

func TestPairingWaitsWhileThePlainCopyIsRemoved(t *testing.T) {
	passwords := &hookedPasswords{memoryPasswords: memoryPasswords{check: checkCorrect}}
	agent := newTestAgent(t, &passwordScreen{}, passwords)
	current := newCurrentPhone(t, agent)
	token, _ := agent.auth.StartPairing()
	current.pair(token)
	agent.background.Wait()
	agent.state.Devices[0].OpenedSealed = true
	passwords.password = "hunter2"

	// An older app pairs while the agent is deciding to drop the plain copy, which that app would need.
	older := newPhone(t, agent)
	paired := make(chan struct{})
	passwords.onLoad = func() {
		go func() {
			token, _ := agent.auth.StartPairing()
			older.pair(token)
			close(paired)
		}()
		time.Sleep(50 * time.Millisecond)
	}
	passwords.onClear = func() {
		select {
		case <-paired:
			t.Error("an iPhone paired between deciding to remove the plain copy and removing it")
		default:
		}
	}
	agent.passwordMu.Lock()
	agent.sealMissing("hunter2", agent.passwordGeneration)
	agent.passwordMu.Unlock()
	<-paired
}

func TestRelayCantAddOrReplacePasswordKeys(t *testing.T) {
	screen := &passwordScreen{}
	passwords := &memoryPasswords{password: "hunter2", check: checkCorrect}
	agent := newTestAgent(t, screen, passwords)
	older := newPhone(t, agent)
	token, _ := agent.auth.StartPairing()
	older.pair(token)

	// A relay adds its own password key to an older app's command: the signature no longer matches.
	attacker, _ := ecdh.P256().GenerateKey(rand.Reader)
	_, hello := older.call("/v1/hello", HelloRequest{DeviceID: older.deviceID})
	request := older.command(actionLock, hello, "")
	request.PasswordKey = b64(attacker.PublicKey().Bytes())
	if status, _ := older.call("/v1/command", request); status != 403 || len(agent.state.Devices[0].PasswordKey) != 0 {
		t.Fatalf("injected password key: %d, registered %v", status, agent.state.Devices[0].PasswordKey)
	}

	// A registered key isn't replaced, even by a correctly signed command.
	current := newCurrentPhone(t, agent)
	token, _ = agent.auth.StartPairing()
	current.pair(token)
	agent.background.Wait()
	registered := agent.state.Devices[1].PasswordKey
	_, hello = current.call("/v1/hello", HelloRequest{DeviceID: current.deviceID})
	request = CommandRequest{DeviceID: current.deviceID, Action: actionStatus, Nonce: hello["nonce"].(string),
		PasswordKey: b64(attacker.PublicKey().Bytes())}
	sessionKey := ""
	if challenge, ok := hello["sealedPassword"].(map[string]any); ok {
		sessionKey = challenge["sessionKey"].(string)
	}
	request.Signature = current.signMessage(signedMessageV2(agent.state.MachineID, current.deviceID, actionStatus, request.Nonce,
		sessionKey, request.PasswordKey, nil))
	if status, _ := current.call("/v1/command", request); status != 200 {
		t.Fatalf("status: %d", status)
	}
	if string(agent.state.Devices[1].PasswordKey) != string(registered) {
		t.Fatal("a registered password key was replaced")
	}
}

func TestPairingAgainWithTheSameIDDropsTheOldSealedCopy(t *testing.T) {
	agent := newTestAgent(t, &passwordScreen{}, &memoryPasswords{check: checkCorrect})
	phone := newCurrentPhone(t, agent)
	token, _ := agent.auth.StartPairing()
	phone.pair(token)
	agent.setPassword("hunter2")
	phone.passwordKey, _ = ecdh.P256().GenerateKey(rand.Reader)
	token, _ = agent.auth.StartPairing()
	if status, _ := phone.pair(token); status != 200 {
		t.Fatalf("pairing again: %d", status)
	}
	agent.background.Wait()
	sealed, ok := agent.state.SealedPasswords[phone.deviceID]
	if !ok {
		// Nothing to seal from: the keyring has no plain copy here.
		return
	}
	if _, err := openPassword(sealed, phone.wrap(b64(sealed.Key), b64(fixedKey(t, 0x33).PublicKey().Bytes()), "n"), fixedKey(t, 0x33),
		agent.state.MachineID, phone.deviceID, "n"); err != nil {
		t.Fatal("the sealed copy is still the one for the old key")
	}
}
