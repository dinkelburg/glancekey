package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// cardSender collects what runCard sends.
func cardSender(t *testing.T, agent *Agent) (chan Card, func()) {
	sent := make(chan Card, 16)
	done := make(chan struct{})
	go agent.runCard(done, func(data []byte) error {
		var message RelayCard
		if err := json.Unmarshal(data, &message); err != nil {
			t.Error(err)
		}
		sent <- message.Card
		return nil
	})
	return sent, func() { close(done) }
}

func nextCard(t *testing.T, sent chan Card) Card {
	t.Helper()
	select {
	case card := <-sent:
		return card
	case <-time.After(5 * time.Second):
		t.Fatal("no card sent")
		return Card{}
	}
}

func noCard(t *testing.T, sent chan Card) {
	t.Helper()
	select {
	case card := <-sent:
		t.Fatalf("unexpected card %+v", card)
	case <-time.After(cardCheckInterval + time.Second):
	}
}

func TestCardFollowsLockAndApprovals(t *testing.T) {
	s := newApprovalSetup(t)
	screen := s.agent.screen.(*fakeScreen)
	sent, stop := cardSender(t, s.agent)
	defer stop()

	// Nothing to send until an iPhone gives its card.
	noCard(t, sent)
	card := strings.Repeat("ab", 32)
	s.phone.call("/v1/hello", HelloRequest{DeviceID: s.phone.deviceID, CardID: &card})
	if reloaded, _ := loadState(); reloaded.Devices[0].CardID != card {
		t.Fatal("card id not saved")
	}
	got := nextCard(t, sent)
	if len(got.Cards) != 1 || got.Cards[0] != card || got.Locked == nil || *got.Locked || len(got.Approvals) != 0 {
		t.Fatalf("first card %+v", got)
	}
	// The same card isn't sent again.
	noCard(t, sent)

	screen.Lock()
	if got := nextCard(t, sent); got.Locked == nil || !*got.Locked {
		t.Fatalf("after locking %+v", got)
	}

	result := s.check("10s")
	got = nextCard(t, sent)
	if len(got.Approvals) != 1 || got.Approvals[0].Title == "" || got.Approvals[0].ExpiresIn <= 0 {
		t.Fatalf("waiting %+v", got)
	}
	approval := s.phone.waitForApproval()
	s.phone.answer(actionDeny, approval, "")
	if got := nextCard(t, sent); len(got.Approvals) != 0 {
		t.Fatalf("after denying %+v", got)
	}
	exitStatus(t, result)

	// Turning the card off: nothing more is sent.
	empty := ""
	s.phone.call("/v1/hello", HelloRequest{DeviceID: s.phone.deviceID, CardID: &empty})
	screen.Unlock("")
	noCard(t, sent)
}

func TestCardIgnoresInvalidIDs(t *testing.T) {
	s := newApprovalSetup(t)
	bad := "../" + strings.Repeat("a", 61)
	s.phone.call("/v1/hello", HelloRequest{DeviceID: s.phone.deviceID, CardID: &bad})
	if _, ok := s.agent.currentCard(); ok || s.agent.state.Devices[0].CardID != "" {
		t.Fatal("invalid card id saved")
	}
}

func TestPhoneWithACardIsNotNotified(t *testing.T) {
	s := newApprovalSetup(t)
	pushToken, card := strings.Repeat("0123456789abcdef", 4), strings.Repeat("ab", 32)
	s.phone.call("/v1/hello", HelloRequest{DeviceID: s.phone.deviceID, PushToken: &pushToken, CardID: &card})
	sent := make(chan []byte, 4)
	s.agent.setRelaySender(func(data []byte) error { sent <- data; return nil })

	result := s.check("5s")
	approval := s.phone.waitForApproval()
	select {
	case data := <-sent:
		t.Fatalf("sent %s; the card notifies this iPhone", data)
	case <-time.After(500 * time.Millisecond):
	}
	s.phone.answer(actionDeny, approval, "")
	exitStatus(t, result)
}
