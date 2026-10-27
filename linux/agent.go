package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
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

	// passwordMu serializes everything that changes where the password is kept (the sealed copies and the
	// keyring's plain copy) or which iPhones it's kept for, keyring calls included, so a decision such as "every
	// iPhone has a sealed copy, drop the plain one" still holds when it's carried out. Take it before mu.
	passwordMu sync.Mutex

	mu    sync.Mutex
	state *State
	// passwordGeneration changes when the password is set or forgotten, so an unlock that read the previous one
	// doesn't seal it afterwards.
	passwordGeneration int
	// background is password work that runs after a reply, such as sealing to an iPhone that just paired.
	background  sync.WaitGroup
	busy        bool
	relayStatus string
	// toRelay sends a message over the relay connection while there is one.
	toRelay   func([]byte) error
	approvals map[string]*pendingApproval
	// cardSignal makes runCard look at the lock screen card right away instead of at its next check.
	cardSignal chan struct{}
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
		cardSignal:  make(chan struct{}, 1),
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
	a.passwordMu.Lock()
	a.mu.Lock()
	previous := a.state.Devices
	var devices []PairedDevice
	for _, existing := range a.state.Devices {
		if existing.ID != device.ID {
			devices = append(devices, existing)
		}
	}
	a.state.Devices = append(devices, device)
	// A copy sealed to an earlier pairing with the same id is sealed to a key this iPhone no longer has.
	oldSealed, hadSealed := a.state.SealedPasswords[device.ID]
	delete(a.state.SealedPasswords, device.ID)
	if err := a.state.save(); err != nil {
		a.state.Devices = previous
		if hadSealed {
			a.state.SealedPasswords[device.ID] = oldSealed
		}
		a.mu.Unlock()
		a.passwordMu.Unlock()
		return nil, requestError{500, "Couldn't save the pairing: " + err.Error()}
	}
	response := PairResponse{MachineID: a.state.MachineID, MachineName: a.state.MachineName}
	a.mu.Unlock()
	a.passwordMu.Unlock()
	log.Printf("Paired %s", device.Name)
	if len(device.PasswordKey) > 0 {
		// After the reply: the keyring can be slow, and the iPhone gives up on pairing after a few seconds.
		a.background.Add(1)
		go func() {
			defer a.background.Done()
			a.passwordMu.Lock()
			defer a.passwordMu.Unlock()
			a.sealFromKeyring()
		}()
	}
	return response, nil
}

func (a *Agent) hello(body []byte) (any, error) {
	var req HelloRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	a.mu.Lock()
	known, hasPasswordKey, cardChanged := false, false, false
	for i, device := range a.state.Devices {
		if device.ID != req.DeviceID {
			continue
		}
		known, hasPasswordKey = true, len(device.PasswordKey) > 0
		changed := false
		if token := req.PushToken; token != nil && *token != device.PushToken && (*token == "" || validPushToken(*token)) {
			a.state.Devices[i].PushToken = *token
			changed = true
		}
		if card := req.CardID; card != nil && *card != device.CardID && (*card == "" || validCardID(*card)) {
			a.state.Devices[i].CardID = *card
			changed, cardChanged = true, true
		}
		if changed {
			if err := a.state.save(); err != nil {
				log.Printf("Couldn't save state: %v", err)
			}
		}
		break
	}
	sealed, hasSealed := a.state.SealedPasswords[req.DeviceID]
	machineID, machineName := a.state.MachineID, a.state.MachineName
	a.mu.Unlock()
	if !known {
		return nil, errUnknownDevice
	}
	if cardChanged {
		a.cardChanged()
	}
	response := HelloResponse{MachineID: machineID, MachineName: machineName, Approvals: a.waitingApprovals(),
		WantsPasswordKey: !hasPasswordKey && a.screen.NeedsPassword()}
	if hasSealed {
		nonce, sessionKey, err := a.auth.IssueNonceWithSession(req.DeviceID)
		if err != nil {
			return nil, err
		}
		response.Nonce = nonce
		response.SealedPassword = &SealedPasswordChallenge{SealKey: base64.StdEncoding.EncodeToString(sealed.Key),
			SessionKey: base64.StdEncoding.EncodeToString(sessionKey)}
	} else {
		response.Nonce = a.auth.IssueNonce(req.DeviceID)
	}
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
	device, session, err := a.auth.Verify(req, devices)
	if err != nil {
		return nil, err
	}
	if req.PasswordKey != "" {
		// After the command, so an unlock still finds the keyring's plain password before it's sealed and removed.
		defer a.registerPasswordKey(device, req.PasswordKey)
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
		response, err = a.unlock(device, session, req)
	default:
		return nil, requestError{400, "Unknown action."}
	}
	if err != nil {
		return nil, err
	}

	a.markUsed(device.ID)
	if req.Action != actionStatus {
		log.Printf("%s: %s", device.Name, response.Message)
		a.cardChanged()
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

func (a *Agent) unlock(device PairedDevice, session *ecdh.PrivateKey, req CommandRequest) (CommandResponse, error) {
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
		var generation int
		var opened bool
		if password, generation, opened, err = a.savedPassword(device, session, req); err != nil {
			return CommandResponse{}, err
		}
		if a.passwords.Check(password) == checkWrong {
			return CommandResponse{}, requestError{409, "The saved password is out of date. Run `" + agentCommand + " set-password` again."}
		}
		// Once the screen is done: note that this iPhone's sealed copy works and seal it again under a fresh key,
		// so a key that left this iPhone is useless from now on; then seal it for an iPhone that has no copy yet.
		defer func() {
			a.passwordMu.Lock()
			defer a.passwordMu.Unlock()
			if opened {
				a.resealOpened(device.ID, password, generation)
			}
			a.sealMissing(password, generation)
		}()
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

// savedPassword opens the password sealed to device with the key it wrapped for this challenge, or else reads the
// keyring's plain copy (an iPhone on an older app, or one that has no sealed copy yet). It also returns the
// password generation it read, and whether it came from the sealed copy.
func (a *Agent) savedPassword(device PairedDevice, session *ecdh.PrivateKey, req CommandRequest) (password string, generation int, opened bool, err error) {
	a.mu.Lock()
	sealed, hasSealed := a.state.SealedPasswords[device.ID]
	machineID, machineName := a.state.MachineID, a.state.MachineName
	generation = a.passwordGeneration
	a.mu.Unlock()
	if hasSealed && req.WrappedKey != nil {
		if password, err = openPassword(sealed, *req.WrappedKey, session, machineID, device.ID, req.Nonce); err != nil {
			// Usually the password was sealed again between hello and this command.
			return "", 0, false, requestError{409, fmt.Sprintf("This iPhone couldn't open the password saved on %s. Try again; if it keeps happening, run `%s set-password` there.", machineName, agentCommand)}
		}
		return password, generation, true, nil
	}
	password, err = a.passwords.Load()
	switch {
	case err == nil:
		return password, generation, false, nil
	case hasSealed && session == nil:
		// Its hello came before this iPhone's sealed copy existed.
		return "", 0, false, requestError{409, "The request was out of date. Try again."}
	case hasSealed:
		return "", 0, false, requestError{409, fmt.Sprintf("Update %s on your iPhone to unlock %s.", appName, machineName)}
	case errors.Is(err, errNoPassword):
		return "", 0, false, requestError{409, fmt.Sprintf("No password saved on %s for this iPhone. Run `%s set-password` there.", machineName, agentCommand)}
	default:
		return "", 0, false, requestError{409, "Couldn't read the saved password: " + err.Error()}
	}
}

// resealOpened notes that device opened its sealed copy (so its password key works on this iPhone) and seals the
// password to it again under a fresh one-time key. The caller holds passwordMu.
func (a *Agent) resealOpened(deviceID, password string, generation int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if generation != a.passwordGeneration {
		return
	}
	for i := range a.state.Devices {
		device := &a.state.Devices[i]
		if device.ID != deviceID || len(device.PasswordKey) == 0 {
			continue
		}
		fresh, err := sealPassword(password, device.PasswordKey, a.state.MachineID, device.ID)
		if err != nil {
			log.Printf("Couldn't seal the password again for %s: %v", device.Name, err)
			return
		}
		previous, wasOpened := a.state.SealedPasswords[device.ID], device.OpenedSealed
		a.state.SealedPasswords[device.ID], device.OpenedSealed = fresh, true
		if err := a.state.save(); err != nil {
			log.Printf("Couldn't save state: %v", err)
			a.state.SealedPasswords[device.ID], device.OpenedSealed = previous, wasOpened
		}
		return
	}
}

// registerPasswordKey keeps the password key an iPhone sent with a signed command, if it has none yet, and seals
// the keyring's plain password to it.
func (a *Agent) registerPasswordKey(device PairedDevice, encoded string) {
	key, err := parsePasswordKey(encoded)
	if err != nil {
		log.Printf("%s sent an invalid password key", device.Name)
		return
	}
	a.passwordMu.Lock()
	defer a.passwordMu.Unlock()
	a.mu.Lock()
	registered := -1
	for i := range a.state.Devices {
		if a.state.Devices[i].ID == device.ID && len(a.state.Devices[i].PasswordKey) == 0 {
			a.state.Devices[i].PasswordKey = key
			registered = i
			break
		}
	}
	if registered >= 0 {
		if err := a.state.save(); err != nil {
			log.Printf("Couldn't save state: %v", err)
			a.state.Devices[registered].PasswordKey = nil
			registered = -1
		}
	}
	a.mu.Unlock()
	if registered >= 0 {
		log.Printf("%s registered its password key", device.Name)
		a.sealFromKeyring()
	}
}

// sealFromKeyring seals the keyring's plain password for iPhones that can have a sealed copy but don't yet.
// The caller holds passwordMu.
func (a *Agent) sealFromKeyring() {
	a.mu.Lock()
	generation := a.passwordGeneration
	a.mu.Unlock()
	password, err := a.passwords.Load()
	if err != nil || a.passwords.Check(password) == checkWrong {
		return
	}
	a.sealMissing(password, generation)
}

// sealMissing seals password (already checked, and read at generation) to every iPhone that has a password key but
// no sealed copy, and removes the keyring's plain copy once every paired iPhone has opened its own sealed copy. Until
// an iPhone has, the plain copy is the way back if its password key doesn't work. The caller holds passwordMu.
func (a *Agent) sealMissing(password string, generation int) {
	a.mu.Lock()
	if generation != a.passwordGeneration {
		// Set or forgotten since it was read.
		a.mu.Unlock()
		return
	}
	var added, names []string
	for _, device := range a.state.Devices {
		if _, done := a.state.SealedPasswords[device.ID]; done || len(device.PasswordKey) == 0 {
			continue
		}
		sealed, err := sealPassword(password, device.PasswordKey, a.state.MachineID, device.ID)
		if err != nil {
			log.Printf("Couldn't seal the password for %s: %v", device.Name, err)
			continue
		}
		if a.state.SealedPasswords == nil {
			a.state.SealedPasswords = map[string]SealedPassword{}
		}
		a.state.SealedPasswords[device.ID] = sealed
		added, names = append(added, device.ID), append(names, device.Name)
	}
	if len(added) > 0 {
		if err := a.state.save(); err != nil {
			// Not on disk, so it doesn't count: the keyring keeps the plain copy.
			log.Printf("Couldn't save state: %v", err)
			for _, id := range added {
				delete(a.state.SealedPasswords, id)
			}
			a.mu.Unlock()
			return
		}
		log.Printf("Sealed the password to %s", strings.Join(names, ", "))
	}
	allOpened := a.allOpened()
	a.mu.Unlock()
	if allOpened {
		a.dropPlainCopy()
	}
}

// allOpened says whether every paired iPhone has its own sealed copy and has opened one before. The caller holds a.mu.
func (a *Agent) allOpened() bool {
	for _, device := range a.state.Devices {
		if _, ok := a.state.SealedPasswords[device.ID]; !ok || !device.OpenedSealed {
			return false
		}
	}
	return len(a.state.Devices) > 0
}

// dropPlainCopy removes the keyring's plain password, if there is one. The caller holds passwordMu and has checked
// allOpened.
func (a *Agent) dropPlainCopy() {
	if _, err := a.passwords.Load(); err != nil {
		return
	}
	if err := a.passwords.Clear(); err != nil {
		log.Printf("Couldn't remove the plain password from the keyring: %v", err)
		return
	}
	log.Print("Removed the plain password from the keyring: every paired iPhone opens its own sealed copy")
}

// setPassword checks password and saves it: sealed to every paired iPhone with a password key, and plain in the
// keyring as long as an iPhone has none (or none is paired yet). It returns what happened, for the terminal.
func (a *Agent) setPassword(password string) (string, error) {
	note := ""
	switch a.passwords.Check(password) {
	case checkWrong:
		return "", fmt.Errorf("that isn't the login password for %s", username())
	case checkUnknown:
		note = "Couldn't verify the password here; saved it anyway. "
	}
	a.passwordMu.Lock()
	defer a.passwordMu.Unlock()
	a.mu.Lock()
	sealed := map[string]SealedPassword{}
	var older []string
	for _, device := range a.state.Devices {
		if len(device.PasswordKey) == 0 {
			older = append(older, device.Name)
			continue
		}
		s, err := sealPassword(password, device.PasswordKey, a.state.MachineID, device.ID)
		if err != nil {
			a.mu.Unlock()
			return "", err
		}
		sealed[device.ID] = s
	}
	previous := a.state.SealedPasswords
	a.state.SealedPasswords = sealed
	if err := a.state.save(); err != nil {
		a.state.SealedPasswords = previous
		a.mu.Unlock()
		return "", err
	}
	a.passwordGeneration++
	paired, allOpened := len(a.state.Devices), a.allOpened()
	a.mu.Unlock()

	if allOpened {
		if _, err := a.passwords.Load(); err == nil {
			if err := a.passwords.Clear(); err != nil {
				return "", fmt.Errorf("couldn't remove the old copy from the keyring: %w", err)
			}
		}
		return note + "Saved, encrypted so that only your paired iPhone(s) can open it.", nil
	}
	if err := a.passwords.Save(password); err != nil {
		return "", fmt.Errorf("saving to the keyring: %w", err)
	}
	switch {
	case paired == 0:
		return note + "Saved in your keyring. Once you pair your iPhone, it's encrypted so that only that iPhone can open it.", nil
	case len(older) > 0:
		return note + fmt.Sprintf("Saved. It also stays in your keyring until %s has the latest %s app and has unlocked once.",
			strings.Join(older, ", "), appName), nil
	default:
		return note + "Saved, encrypted to your iPhone(s). A plain copy stays in your keyring until each of them has unlocked this computer once.", nil
	}
}

// forgetPassword removes the sealed copies and the keyring's plain one.
func (a *Agent) forgetPassword() error {
	a.passwordMu.Lock()
	defer a.passwordMu.Unlock()
	a.mu.Lock()
	previous := a.state.SealedPasswords
	a.state.SealedPasswords = nil
	if err := a.state.save(); err != nil {
		a.state.SealedPasswords = previous
		a.mu.Unlock()
		return err
	}
	a.passwordGeneration++
	a.mu.Unlock()
	if _, err := a.passwords.Load(); errors.Is(err, errNoPassword) {
		return nil
	}
	return a.passwords.Clear()
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
