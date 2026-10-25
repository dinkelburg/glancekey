package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

// Approvals: a password prompt (sudo, polkit) runs the root-owned checker (checker.go), which asks this agent
// over the control socket to show the request on the iPhone. The agent lists it in its hello answers, notifies
// the iPhone through ntfy and passes the iPhone's answer back to the checker, which verifies the signature
// itself. The agent never decides on its own, so a compromised agent can't approve anything.

// checkerMessage is one line between the checker and the agent, after the checker's "approval" request.
type checkerMessage struct {
	// Waiting: the agent accepted the request and is waiting for the iPhone.
	Waiting bool `json:"waiting,omitempty"`
	// Decision is "approve" (with DeviceID and Signature) or "deny".
	Decision  string `json:"decision,omitempty"`
	DeviceID  string `json:"deviceId,omitempty"`
	Signature string `json:"signature,omitempty"`
	// Accepted is the checker's verdict on an approval, which the agent passes on to the iPhone.
	Accepted *bool  `json:"accepted,omitempty"`
	Error    string `json:"error,omitempty"`
}

type approvalAnswer struct {
	decision  string
	device    PairedDevice
	signature string
}

type pendingApproval struct {
	approval Approval
	deadline time.Time
	answered bool
	answers  chan approvalAnswer
	verdicts chan checkerMessage
}

const maxApprovalWait = 2 * time.Minute

func validateApproval(approval *Approval) error {
	switch {
	case approval == nil || approval.ID == "" || approval.Nonce == "" || approval.Title == "":
		return errors.New("incomplete approval request")
	case len(approval.ID) > 100 || len(approval.Nonce) > 100 || utf8.RuneCountInString(approval.Title) > 300 ||
		utf8.RuneCountInString(approval.Detail) > 300:
		return errors.New("approval request too long")
	case strings.ContainsAny(approval.Title+approval.Detail, "\r\n"):
		return errors.New("approval request has line breaks")
	case approval.ExpiresIn < 1 || time.Duration(approval.ExpiresIn)*time.Second > maxApprovalWait:
		return errors.New("approval request has an invalid timeout")
	}
	return nil
}

// serveApproval handles a checker's "approval" request until the iPhone answers, the time runs out or the
// checker hangs up (for example because you pressed Ctrl-C in sudo).
func (a *Agent) serveApproval(conn net.Conn, decoder *json.Decoder, approval *Approval) {
	encoder := json.NewEncoder(conn)
	reply := func(message checkerMessage) bool {
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		return encoder.Encode(message) == nil
	}
	if err := validateApproval(approval); err != nil {
		reply(checkerMessage{Error: err.Error()})
		return
	}
	if err := a.phoneReachable(); err != nil {
		reply(checkerMessage{Error: err.Error()})
		return
	}

	pending := &pendingApproval{
		approval: *approval,
		deadline: a.now().Add(time.Duration(approval.ExpiresIn) * time.Second),
		answers:  make(chan approvalAnswer, 1),
		verdicts: make(chan checkerMessage, 1),
	}
	a.mu.Lock()
	a.approvals[approval.ID] = pending
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.approvals, approval.ID)
		a.mu.Unlock()
	}()

	conn.SetDeadline(time.Time{})
	if !reply(checkerMessage{Waiting: true}) {
		return
	}
	log.Printf("Waiting for your iPhone to approve: %s", approval.Title)
	go a.notifyPhones()

	// The checker only writes again after the iPhone answered, so anything earlier means it hung up.
	done := make(chan struct{})
	defer close(done)
	messages := make(chan checkerMessage)
	go func() {
		defer close(messages)
		for {
			var message checkerMessage
			if decoder.Decode(&message) != nil {
				return
			}
			select {
			case messages <- message:
			case <-done:
				return
			}
		}
	}()

	timer := time.NewTimer(time.Until(pending.deadline))
	defer timer.Stop()
	select {
	case answer := <-pending.answers:
		reply(checkerMessage{Decision: answer.decision, DeviceID: answer.device.ID, Signature: answer.signature})
		if answer.decision != string(actionApprove) {
			return
		}
		verdict := checkerMessage{Error: "The computer didn't confirm the approval."}
		select {
		case message, ok := <-messages:
			if ok && message.Accepted != nil {
				verdict = message
			}
		case <-time.After(10 * time.Second):
		}
		pending.verdicts <- verdict
	case <-messages:
		log.Printf("The request was cancelled: %s", approval.Title)
	case <-timer.C:
		reply(checkerMessage{Error: "No answer from your iPhone."})
		log.Printf("No answer from your iPhone: %s", approval.Title)
	}
}

// phoneReachable is a quick check so the checker doesn't keep you waiting when no iPhone could answer.
func (a *Agent) phoneReachable() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.state.Devices) == 0 {
		return errors.New("no iPhone is paired")
	}
	if a.relayStatus != "connected" {
		return errors.New("not connected to the relay")
	}
	return nil
}

// waitingApprovals lists the requests the iPhone can still answer, for hello.
func (a *Agent) waitingApprovals() []Approval {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	var list []Approval
	for _, pending := range a.approvals {
		left := pending.deadline.Sub(now)
		if pending.answered || left <= 0 {
			continue
		}
		approval := pending.approval
		approval.ExpiresIn = int((left + time.Second - 1) / time.Second)
		list = append(list, approval)
	}
	return list
}

// answerApproval handles the iPhone's approve or deny.
func (a *Agent) answerApproval(req CommandRequest) (any, error) {
	a.mu.Lock()
	pending := a.approvals[req.ApprovalID]
	var device *PairedDevice
	for i := range a.state.Devices {
		if a.state.Devices[i].ID == req.DeviceID {
			copied := a.state.Devices[i]
			device = &copied
		}
	}
	a.mu.Unlock()
	if device == nil {
		return nil, errUnknownDevice
	}
	if pending == nil || !a.now().Before(pending.deadline) {
		return nil, errApprovalGone
	}
	// Check the signature here as well, so a bad one gets a clear error without using up the request.
	if req.Action == actionApprove &&
		!device.validSignature(approvalMessage(a.state.MachineID, device.ID, pending.approval), req.Signature) {
		return nil, errBadSignature
	}

	a.mu.Lock()
	if pending.answered {
		a.mu.Unlock()
		return nil, errApprovalGone
	}
	pending.answered = true
	a.mu.Unlock()
	pending.answers <- approvalAnswer{decision: string(req.Action), device: *device, signature: req.Signature}

	if req.Action == actionDeny {
		log.Printf("%s denied: %s", device.Name, pending.approval.Title)
		return CommandResponse{OK: true, Message: "Denied. It asks for the password instead."}, nil
	}
	select {
	case verdict := <-pending.verdicts:
		if verdict.Accepted == nil || !*verdict.Accepted {
			message := verdict.Error
			if message == "" {
				message = "The computer rejected the approval."
			}
			log.Printf("Approval from %s rejected: %s", device.Name, message)
			return nil, requestError{403, message}
		}
	case <-time.After(15 * time.Second):
		return nil, errApprovalGone
	}
	a.markUsed(device.ID)
	log.Printf("%s approved: %s", device.Name, pending.approval.Title)
	return CommandResponse{OK: true, Message: "Approved"}, nil
}

// notifyPhones posts to the paired iPhones' ntfy topics. Tapping the notification opens FaceUnlock.
func (a *Agent) notifyPhones() {
	a.mu.Lock()
	machineName := a.state.MachineName
	topics := map[string]bool{}
	for _, device := range a.state.Devices {
		if validTopic(device.NotifyTopic) {
			topics[device.NotifyTopic] = true
		}
	}
	a.mu.Unlock()
	for topic := range topics {
		if err := postNotification(topic, machineName); err != nil {
			log.Printf("Couldn't send the notification: %v", err)
		}
	}
}

func postNotification(topic, machineName string) error {
	server := os.Getenv("FACEUNLOCK_NTFY")
	if server == "" {
		server = ntfyServer
	}
	body, _ := json.Marshal(map[string]any{
		"topic":    topic,
		"title":    machineName + " is waiting for you",
		"message":  "Tap to approve or deny with FaceUnlock.",
		"click":    notifyOpenURL,
		"priority": 4,
		"tags":     []string{"closed_lock_with_key"},
	})
	client := http.Client{Timeout: 10 * time.Second}
	response, err := client.Post(strings.TrimRight(server, "/"), "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	response.Body.Close()
	if response.StatusCode >= 300 {
		return errors.New("ntfy answered " + response.Status)
	}
	return nil
}
