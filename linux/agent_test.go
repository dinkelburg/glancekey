package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

type phone struct {
	t        *testing.T
	agent    *Agent
	key      *ecdsa.PrivateKey
	deviceID string
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
	proof := base64.StdEncoding.EncodeToString(pairingProof(token, p.agent.state.MachineID, p.deviceID, "Test iPhone", publicKey))
	return p.call("/v1/pair", PairRequest{DeviceID: p.deviceID, DeviceName: "Test iPhone", PublicKey: publicKey, Proof: proof})
}

func (p *phone) sign(action Action, nonce string) string {
	digest := sha256.Sum256(signedMessage(p.agent.state.MachineID, p.deviceID, action, nonce))
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
