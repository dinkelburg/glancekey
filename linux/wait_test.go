package main

import (
	"testing"
)

func TestApprovalWaitComesFromTheAgent(t *testing.T) {
	s := newApprovalSetup(t)
	if err := s.agent.setApprovalWait(300); err != nil {
		t.Fatal(err)
	}
	// The checker's own timeout is the fallback; the agent's setting wins.
	result := s.check("5s")
	approval := s.phone.waitForApproval()
	if approval.ExpiresIn < 290 || approval.ExpiresIn > 300 {
		t.Fatalf("the iPhone sees %d seconds left", approval.ExpiresIn)
	}
	s.phone.answer(actionDeny, approval, "")
	exitStatus(t, result)
}

func TestSetWaitFromTheIPhone(t *testing.T) {
	s := newApprovalSetup(t)
	_, hello := s.phone.call("/v1/hello", HelloRequest{DeviceID: s.phone.deviceID})
	if hello["approvalWait"] != float64(30) {
		t.Fatalf("default wait: %v", hello["approvalWait"])
	}
	send := func(signed, sent int) (int, map[string]any) {
		_, hello := s.phone.call("/v1/hello", HelloRequest{DeviceID: s.phone.deviceID})
		nonce := hello["nonce"].(string)
		return s.phone.call("/v1/command", CommandRequest{DeviceID: s.phone.deviceID, Action: actionSetWait, Nonce: nonce,
			Wait: sent, Signature: s.phone.signMessage(waitMessage(s.agent.state.MachineID, s.phone.deviceID, nonce, signed))})
	}
	if status, body := send(untilAnswered, untilAnswered); status != 200 || body["ok"] != true || s.agent.approvalWait() != untilAnswered {
		t.Fatalf("set: %d %v", status, body)
	}
	if reloaded, _ := loadState(); reloaded.ApprovalWait != untilAnswered {
		t.Fatal("not saved")
	}
	// A relay that changes the value fails the signature; a value that isn't offered is refused.
	if status, _ := send(300, 60); status != 403 || s.agent.approvalWait() != untilAnswered {
		t.Fatalf("changed value: %d", status)
	}
	if status, _ := send(42, 42); status != 400 {
		t.Fatalf("odd value: %d", status)
	}
}

func TestParseApprovalWait(t *testing.T) {
	for text, want := range map[string]int{"30s": 30, "1m": 60, "5m": 300, "15m": 900, "until-answered": untilAnswered} {
		if got, err := parseApprovalWait(text); err != nil || got != want {
			t.Errorf("%s: %d %v", text, got, err)
		}
	}
	for _, text := range []string{"45s", "2h", "forever", ""} {
		if _, err := parseApprovalWait(text); err == nil {
			t.Errorf("%s accepted", text)
		}
	}
}
