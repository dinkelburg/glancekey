package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// The CLI talks to the running agent over a Unix socket only you can open.

type controlRequest struct {
	Command  string    `json:"command"`
	Argument string    `json:"argument,omitempty"`
	Approval *Approval `json:"approval,omitempty"`
}

type deviceInfo struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Key        string     `json:"key,omitempty"` // keyFingerprint
	PairedAt   time.Time  `json:"pairedAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	// PasswordSealed: the password is sealed to this iPhone (seal.go).
	PasswordSealed bool `json:"passwordSealed,omitempty"`
	// OpenedSealed: the iPhone has opened its sealed copy before.
	OpenedSealed bool `json:"openedSealed,omitempty"`
}

type statusInfo struct {
	MachineName    string `json:"machineName"`
	MachineID      string `json:"machineId"`
	Relay          string `json:"relay"`
	RelayStatus    string `json:"relayStatus"`
	Screen         string `json:"screen"`
	Locked         *bool  `json:"locked,omitempty"`
	LockError      string `json:"lockError,omitempty"`
	PasswordNeeded bool   `json:"passwordNeeded"`
	PasswordSaved  bool   `json:"passwordSaved"`
	// PasswordInKeyring: a plain copy is in the keyring, for iPhones without a sealed one.
	PasswordInKeyring bool         `json:"passwordInKeyring,omitempty"`
	Pairing           bool         `json:"pairing"`
	Devices           []deviceInfo `json:"devices"`
}

type controlResponse struct {
	Error     string      `json:"error,omitempty"`
	Message   string      `json:"message,omitempty"`
	Invite    string      `json:"invite,omitempty"`
	Expires   time.Time   `json:"expires,omitempty"`
	Status    *statusInfo `json:"status,omitempty"`
	Approvers *Approvers  `json:"approvers,omitempty"`
}

// Approvers is who may approve password prompts on this computer. `sudo <agent> enable-sudo` gets it
// from the running agent (or the Mac app) and saves it, root-owned, at approversPath.
type Approvers struct {
	MachineID   string     `json:"machineId"`
	MachineName string     `json:"machineName"`
	Devices     []Approver `json:"devices"`
}

type Approver struct {
	// ID is the iPhone's device id, as the agent and the Mac app hand it to enable-sudo. approvers.json only keeps
	// its SHA-256 (IDHash): anyone on the computer can read the file, and a device id is all a hello needs.
	ID        string `json:"id,omitempty"`
	IDHash    string `json:"idHash,omitempty"`
	Name      string `json:"name"`
	PublicKey []byte `json:"publicKey"`
	// PairedAt is shown when setting up, with the key's fingerprint, so a key paired behind your back stands out.
	PairedAt *time.Time `json:"pairedAt,omitempty"`
}

// key tells iPhones apart whether the device id is there or only its hash (approvers.json from before 1.0.3 has
// the id itself).
func (a Approver) key() string {
	if a.IDHash != "" {
		return a.IDHash
	}
	return deviceIDHash(a.ID)
}

// deviceIDHash is how approvers.json names a device id: hex SHA-256, as in Mac/ControlSocket.swift.
func deviceIDHash(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// hashed is the list as approvers.json keeps it, with the device ids hashed.
func (a *Approvers) hashed() *Approvers {
	copied := *a
	copied.Devices = make([]Approver, len(a.Devices))
	for i, device := range a.Devices {
		device.IDHash, device.ID = device.key(), ""
		copied.Devices[i] = device
	}
	return &copied
}

func controlSocketPath() string {
	if os.Getenv(envPrefix+"CONFIG_DIR") == "" {
		if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
			return filepath.Join(runtimeDir, agentCommand+".sock")
		}
	}
	return filepath.Join(configDir(), "agent.sock")
}

func (a *Agent) serveControl(ctx context.Context) error {
	path := controlSocketPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		listener.Close()
		return err
	}
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("Control socket: %v", err)
			continue
		}
		go func() {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(15 * time.Second))
			decoder := json.NewDecoder(conn)
			var request controlRequest
			if err := decoder.Decode(&request); err != nil {
				return
			}
			if request.Command == "approval" {
				a.serveApproval(conn, decoder, request.Approval)
				return
			}
			json.NewEncoder(conn).Encode(a.control(request))
		}()
	}
}

func (a *Agent) control(request controlRequest) controlResponse {
	switch request.Command {
	case "pair":
		token, expires := a.auth.StartPairing()
		a.mu.Lock()
		invite := PairingInvite{V: protocolVersion, MachineID: a.state.MachineID, MachineName: a.state.MachineName,
			Platform: platformName(), Relay: a.state.relayURL(), Token: token, WantsPasswordKey: a.screen.NeedsPassword()}
		a.mu.Unlock()
		return controlResponse{Invite: invite.URL(), Expires: expires}
	case "cancel-pair":
		a.auth.CancelPairing()
		return controlResponse{}
	case "status":
		return controlResponse{Status: a.status()}
	case "approvers":
		a.mu.Lock()
		defer a.mu.Unlock()
		approvers := &Approvers{MachineID: a.state.MachineID, MachineName: a.state.MachineName, Devices: []Approver{}}
		for _, device := range a.state.Devices {
			pairedAt := device.PairedAt
			approvers.Devices = append(approvers.Devices, Approver{ID: device.ID, Name: device.Name, PublicKey: device.PublicKey, PairedAt: &pairedAt})
		}
		return controlResponse{Approvers: approvers}
	case "set-password":
		message, err := a.setPassword(request.Argument)
		if err != nil {
			return controlResponse{Error: err.Error()}
		}
		log.Print("Saved a new password")
		return controlResponse{Message: message}
	case "set-wait":
		wait, err := parseApprovalWait(request.Argument)
		if err == nil {
			err = a.setApprovalWait(wait)
		}
		if err != nil {
			return controlResponse{Error: err.Error()}
		}
		return controlResponse{Message: waitSaved(wait)}
	case "forget-password":
		if err := a.forgetPassword(); err != nil {
			return controlResponse{Error: err.Error()}
		}
		log.Print("Removed the saved password")
		return controlResponse{}
	case "unpair":
		removed, err := a.unpair(request.Argument)
		if err != nil {
			return controlResponse{Error: err.Error()}
		}
		log.Printf("Removed %s", removed.Name)
		return controlResponse{}
	}
	return controlResponse{Error: "unknown command " + request.Command}
}

func (a *Agent) status() *statusInfo {
	a.mu.Lock()
	info := &statusInfo{
		MachineName:    a.state.MachineName,
		MachineID:      a.state.MachineID,
		Relay:          a.state.relayURL(),
		RelayStatus:    a.relayStatus,
		Screen:         a.screen.Name(),
		PasswordNeeded: a.screen.NeedsPassword(),
	}
	for _, device := range a.state.Devices {
		_, sealed := a.state.SealedPasswords[device.ID]
		info.Devices = append(info.Devices, deviceInfo{device.ID, device.Name, keyFingerprint(device.PublicKey), device.PairedAt, device.LastUsedAt, sealed, device.OpenedSealed})
	}
	anySealed := len(a.state.SealedPasswords) > 0
	a.mu.Unlock()

	info.Pairing = a.auth.PairingActive()
	if locked, err := a.screen.IsLocked(); err != nil {
		info.LockError = err.Error()
	} else {
		info.Locked = &locked
	}
	if info.PasswordNeeded {
		_, err := a.passwords.Load()
		info.PasswordInKeyring = err == nil
		info.PasswordSaved = info.PasswordInKeyring || anySealed
	}
	return info
}

// unpair removes a device by id or (case-insensitive) name.
func (a *Agent) unpair(which string) (PairedDevice, error) {
	a.passwordMu.Lock()
	defer a.passwordMu.Unlock()
	removed, allOpened, err := a.removeDevice(which)
	if err == nil && allOpened {
		// The iPhone that still needed the plain copy is gone.
		a.dropPlainCopy()
	}
	return removed, err
}

func (a *Agent) removeDevice(which string) (removed PairedDevice, allOpened bool, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var matches []int
	for i, device := range a.state.Devices {
		if device.ID == which || strings.EqualFold(device.Name, which) {
			matches = append(matches, i)
		}
	}
	if len(matches) == 0 {
		return PairedDevice{}, false, fmt.Errorf("no paired device called %q", which)
	}
	if len(matches) > 1 {
		return PairedDevice{}, false, fmt.Errorf("several devices are called %q; use the id from `%s status`", which, agentCommand)
	}
	i := matches[0]
	removed = a.state.Devices[i]
	a.state.Devices = append(append([]PairedDevice(nil), a.state.Devices[:i]...), a.state.Devices[i+1:]...)
	delete(a.state.SealedPasswords, removed.ID)
	if err := a.state.save(); err != nil {
		return removed, false, err
	}
	return removed, a.allOpened(), nil
}

func callAgent(request controlRequest) (controlResponse, error) {
	conn, err := net.DialTimeout("unix", controlSocketPath(), 3*time.Second)
	if err != nil {
		return controlResponse{}, errAgentNotRunning
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return controlResponse{}, err
	}
	var response controlResponse
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return controlResponse{}, err
	}
	if response.Error != "" {
		return response, errors.New(response.Error)
	}
	return response, nil
}

var errAgentNotRunning = fmt.Errorf("the agent isn't running. Start it with `systemctl --user start %[1]s` (or `%[1]s run`)", agentCommand)

func platformName() string {
	if runtime.GOOS == "darwin" {
		return "macOS"
	}
	return runtime.GOOS
}
