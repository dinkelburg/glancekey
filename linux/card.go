package main

import (
	"encoding/json"
	"log"
	"sort"
	"time"
)

// The lock screen card: a Live Activity on the iPhone that lists the paired computers, whether each is locked and
// what's waiting for approval, with buttons. The agent sends its own part to the relay whenever it changes; the
// relay combines the computers of each card and pushes it to the iPhone (relay/src/index.ts). The card only
// shows things, and its buttons go through the same signed requests as the app, so the relay can't do more with it
// than it already sees.

// cardCheckInterval is how often the agent looks whether the screen locked or unlocked, while an iPhone has a card.
const cardCheckInterval = 3 * time.Second

// cardChanged makes runCard look right away, after something that may change the card.
func (a *Agent) cardChanged() {
	select {
	case a.cardSignal <- struct{}{}:
	default:
	}
}

// currentCard is what the agent would send for the card now; false when no paired iPhone has a card.
func (a *Agent) currentCard() (Card, bool) {
	a.mu.Lock()
	seen := map[string]bool{}
	card := Card{Cards: []string{}, Approvals: []CardWaiting{}}
	for _, device := range a.state.Devices {
		if validCardID(device.CardID) && !seen[device.CardID] {
			seen[device.CardID] = true
			card.Cards = append(card.Cards, device.CardID)
		}
	}
	a.mu.Unlock()
	if len(card.Cards) == 0 {
		return card, false
	}
	sort.Strings(card.Cards)
	if locked, err := a.screen.IsLocked(); err == nil {
		card.Locked = &locked
	}
	approvals := a.waitingApprovals()
	sort.Slice(approvals, func(i, j int) bool { return approvals[i].ID < approvals[j].ID })
	for _, approval := range approvals {
		card.Approvals = append(card.Approvals, CardWaiting{ID: approval.ID, Title: approval.Title, Detail: approval.Detail,
			ExpiresIn: approval.ExpiresIn})
	}
	return card, true
}

// runCard sends the card over a new relay connection and then whenever it changes, until done closes.
func (a *Agent) runCard(done <-chan struct{}, send func([]byte) error) {
	ticker := time.NewTicker(cardCheckInterval)
	defer ticker.Stop()
	var last *Card
	for {
		if card, ok := a.currentCard(); !ok {
			last = nil
		} else if last == nil || !card.sameAs(*last) {
			data, _ := json.Marshal(RelayCard{Card: card})
			if err := send(data); err != nil {
				log.Printf("Couldn't update the lock screen card: %v", err)
			} else {
				last = &card
			}
		}
		select {
		case <-done:
			return
		case <-ticker.C:
		case <-a.cardSignal:
		}
	}
}
