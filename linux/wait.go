package main

import (
	"fmt"
	"time"
)

// The approval wait: how long sudo and polkit wait for the iPhone before they ask for the password. It's a setting
// of this computer, which the agent hands the checker with each request (checkerMessage.ExpiresIn). You change it
// here with `<agent> set-wait`, or from the iPhone with a signed command (actionSetWait). It never decides an
// approval: the checker still verifies the iPhone's signature against approvers.json itself.

// untilAnswered is the longest wait: in practice, until you approve, deny or give up at the computer (Enter or
// Ctrl-C). The same in Swift (ApprovalWait).
const untilAnswered = 24 * 60 * 60

// approvalWaits are the waits you can choose, in seconds. The first is the default.
var approvalWaits = []int{30, 60, 300, 900, untilAnswered}

func validApprovalWait(seconds int) bool {
	for _, wait := range approvalWaits {
		if seconds == wait {
			return true
		}
	}
	return false
}

// approvalWait is the saved wait, or the default. Only the iPhone and `set-wait` are limited to approvalWaits; any
// wait up to untilAnswered in agent.json works.
func (a *Agent) approvalWait() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state.ApprovalWait > 0 && a.state.ApprovalWait <= untilAnswered {
		return a.state.ApprovalWait
	}
	return approvalWaits[0]
}

func (a *Agent) setApprovalWait(seconds int) error {
	if !validApprovalWait(seconds) {
		return requestError{400, "Choose one of the offered waits."}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	previous := a.state.ApprovalWait
	a.state.ApprovalWait = seconds
	if err := a.state.save(); err != nil {
		a.state.ApprovalWait = previous
		return requestError{500, "Couldn't save the wait: " + err.Error()}
	}
	return nil
}

// parseApprovalWait reads `set-wait`'s argument: 30s, 1m, 5m, 15m or until-answered.
func parseApprovalWait(text string) (int, error) {
	if text == "until-answered" {
		return untilAnswered, nil
	}
	wait, err := time.ParseDuration(text)
	if err != nil || wait%time.Second != 0 || !validApprovalWait(int(wait/time.Second)) {
		return 0, fmt.Errorf("choose 30s, 1m, 5m, 15m or until-answered")
	}
	return int(wait / time.Second), nil
}

// waitSaved says what `set-wait` changed.
func waitSaved(seconds int) string {
	return "sudo and polkit now wait " + describeApprovalWait(seconds) + " for your iPhone."
}

// describeApprovalWait says a wait the way the iPhone app does.
func describeApprovalWait(seconds int) string {
	switch {
	case seconds >= untilAnswered:
		return "until you answer"
	case seconds < 60:
		return fmt.Sprintf("%d seconds", seconds)
	case seconds == 60:
		return "1 minute"
	default:
		return fmt.Sprintf("%d minutes", seconds/60)
	}
}
