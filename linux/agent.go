package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// requestError is a failure the iPhone should show, with the HTTP status the relay returns.
type requestError struct {
	status  int
	message string
}

func (e requestError) Error() string { return e.message }

type Agent struct {
	auth      *Authenticator
	screen    Screen
	passwords PasswordStore
	now       func() time.Time

	mu          sync.Mutex
	state       *State
	busy        bool
	relayStatus string
	// toRelay sends a message over the relay connection while there is one.
	toRelay   func([]byte) error
	approvals map[string]*pendingApproval
}

func newAgent(state *State, screen Screen, passwords PasswordStore) *Agent {
	return &Agent{
		auth:        newAuthenticator(state.MachineID, time.Now),
		screen:      screen,
		passwords:   passwords,
		now:         time.Now,
		state:       state,
		relayStatus: "connecting",
		approvals:   map[string]*pendingApproval{},
	}
}

// handle answers one phone request that arrived through the relay.
func (a *Agent) handle(path string, body []byte) (int, any) {
	var result any
	var err error
	switch path {
	case "/v1/pair":
		result, err = a.pair(body)
	case "/v1/hello":
		result, err = a.hello(body)
	case "/v1/command":
		result, err = a.command(body)
	default:
		return 404, ErrorResponse{Error: "Not found."}
	}

	var auth authError
	var request requestError
	switch {
	case err == nil:
		return 200, result
	case errors.As(err, &auth):
		log.Printf("Rejected a request: %s", auth)
		return 403, ErrorResponse{Error: auth.Error()}
	case errors.As(err, &request):
		log.Print(request.message)
		return request.status, ErrorResponse{Error: request.message}
	default:
		return 400, ErrorResponse{Error: "Bad request."}
	}
}

func (a *Agent) pair(body []byte) (any, error) {
	var req PairRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	device, err := a.auth.CompletePairing(req)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var devices []PairedDevice
	for _, existing := range a.state.Devices {
		if existing.ID != device.ID {
			devices = append(devices, existing)
		}
	}
	a.state.Devices = append(devices, device)
	if err := a.state.save(); err != nil {
		return nil, requestError{500, "Couldn't save the pairing: " + err.Error()}
	}
	log.Printf("Paired %s", device.Name)
	return PairResponse{MachineID: a.state.MachineID, MachineName: a.state.MachineName}, nil
}

func (a *Agent) hello(body []byte) (any, error) {
	var req HelloRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	a.mu.Lock()
	known := false
	for i, device := range a.state.Devices {
		if device.ID != req.DeviceID {
			continue
		}
		known = true
		if token := req.PushToken; token != nil && *token != device.PushToken && (*token == "" || validPushToken(*token)) {
			a.state.Devices[i].PushToken = *token
			if err := a.state.save(); err != nil {
				log.Printf("Couldn't save state: %v", err)
			}
		}
		break
	}
	machineID, machineName := a.state.MachineID, a.state.MachineName
	a.mu.Unlock()
	if !known {
		return nil, errUnknownDevice
	}
	response := HelloResponse{MachineID: machineID, MachineName: machineName, Nonce: a.auth.IssueNonce(req.DeviceID),
		Approvals: a.waitingApprovals()}
	if locked, err := a.screen.IsLocked(); err == nil {
		response.Locked = &locked
	}
	return response, nil
}

func (a *Agent) command(body []byte) (any, error) {
	var req CommandRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if req.Action == actionApprove || req.Action == actionDeny {
		return a.answerApproval(req)
	}
	a.mu.Lock()
	devices := append([]PairedDevice(nil), a.state.Devices...)
	a.mu.Unlock()
	device, err := a.auth.Verify(req, devices)
	if err != nil {
		return nil, err
	}

	a.mu.Lock()
	if a.busy {
		a.mu.Unlock()
		return nil, requestError{409, "Your computer is still busy with the previous request."}
	}
	a.busy = true
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.busy = false
		a.mu.Unlock()
	}()

	var response CommandResponse
	switch req.Action {
	case actionStatus:
		locked, err := a.screen.IsLocked()
		if err != nil {
			return nil, requestError{500, "Couldn't read the lock state: " + err.Error()}
		}
		message := "Unlocked"
		if locked {
			message = "Locked"
		}
		response = CommandResponse{OK: true, Locked: locked, Message: message}
	case actionLock:
		response, err = a.lock()
	case actionUnlock:
		response, err = a.unlock()
	default:
		return nil, requestError{400, "Unknown action."}
	}
	if err != nil {
		return nil, err
	}

	a.markUsed(device.ID)
	if req.Action != actionStatus {
		log.Printf("%s: %s", device.Name, response.Message)
	}
	return response, nil
}

func (a *Agent) lock() (CommandResponse, error) {
	if locked, err := a.screen.IsLocked(); err == nil && locked {
		return CommandResponse{OK: true, Locked: true, Message: "Already locked"}, nil
	}
	if err := a.screen.Lock(); err != nil {
		return CommandResponse{OK: false, Locked: false, Message: "Couldn't lock: " + err.Error()}, nil
	}
	locked := waitFor(4*time.Second, func() bool {
		locked, err := a.screen.IsLocked()
		return err == nil && locked
	})
	if locked {
		return CommandResponse{OK: true, Locked: true, Message: "Locked"}, nil
	}
	return CommandResponse{OK: false, Locked: false, Message: "Asked to lock, but the screen didn't lock"}, nil
}

func (a *Agent) unlock() (CommandResponse, error) {
	locked, err := a.screen.IsLocked()
	if err != nil {
		return CommandResponse{}, requestError{500, "Couldn't read the lock state: " + err.Error()}
	}
	if !locked {
		a.screen.Wake()
		return CommandResponse{OK: true, Locked: false, Message: "Already unlocked"}, nil
	}

	password := ""
	if a.screen.NeedsPassword() {
		password, err = a.passwords.Load()
		if errors.Is(err, errNoPassword) {
			return CommandResponse{}, requestError{409, fmt.Sprintf("No password saved on %s. Run `%s set-password` there.", a.machineName(), agentCommand)}
		} else if err != nil {
			return CommandResponse{}, requestError{409, "Couldn't read the saved password: " + err.Error()}
		}
		if a.passwords.Check(password) == checkWrong {
			return CommandResponse{}, requestError{409, "The saved password is out of date. Run `" + agentCommand + " set-password` again."}
		}
	}

	if err := a.screen.Unlock(password); err != nil {
		return CommandResponse{OK: false, Locked: true, Message: "Couldn't unlock: " + err.Error()}, nil
	}
	unlocked := waitFor(6*time.Second, func() bool {
		locked, err := a.screen.IsLocked()
		return err == nil && !locked
	})
	if unlocked {
		return CommandResponse{OK: true, Locked: false, Message: "Unlocked"}, nil
	}
	return CommandResponse{OK: false, Locked: true, Message: "Tried to unlock, but the screen is still locked"}, nil
}

func (a *Agent) markUsed(deviceID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	for i := range a.state.Devices {
		if a.state.Devices[i].ID == deviceID {
			a.state.Devices[i].LastUsedAt = &now
		}
	}
	if err := a.state.save(); err != nil {
		log.Printf("Couldn't save state: %v", err)
	}
}

func (a *Agent) machineName() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state.MachineName
}

func (a *Agent) setRelayStatus(status string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.relayStatus = status
}

func (a *Agent) setRelaySender(send func([]byte) error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.toRelay = send
}

func waitFor(timeout time.Duration, condition func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if condition() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(250 * time.Millisecond)
	}
}
