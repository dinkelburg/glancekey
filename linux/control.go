package main

import (
	"context"
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
	Command  string `json:"command"`
	Argument string `json:"argument,omitempty"`
}

type deviceInfo struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	PairedAt   time.Time  `json:"pairedAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
}

type statusInfo struct {
	MachineName    string       `json:"machineName"`
	MachineID      string       `json:"machineId"`
	Relay          string       `json:"relay"`
	RelayStatus    string       `json:"relayStatus"`
	Screen         string       `json:"screen"`
	Locked         *bool        `json:"locked,omitempty"`
	LockError      string       `json:"lockError,omitempty"`
	PasswordNeeded bool         `json:"passwordNeeded"`
	PasswordSaved  bool         `json:"passwordSaved"`
	Pairing        bool         `json:"pairing"`
	Devices        []deviceInfo `json:"devices"`
}

type controlResponse struct {
	Error   string      `json:"error,omitempty"`
	Invite  string      `json:"invite,omitempty"`
	Expires time.Time   `json:"expires,omitempty"`
	Status  *statusInfo `json:"status,omitempty"`
}

func controlSocketPath() string {
	if os.Getenv("FACEUNLOCK_CONFIG_DIR") == "" {
		if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
			return filepath.Join(runtimeDir, "faceunlock-agent.sock")
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
			var request controlRequest
			if err := json.NewDecoder(conn).Decode(&request); err != nil {
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
			Platform: platformName(), Relay: a.state.relayURL(), Token: token}
		a.mu.Unlock()
		return controlResponse{Invite: invite.URL(), Expires: expires}
	case "cancel-pair":
		a.auth.CancelPairing()
		return controlResponse{}
	case "status":
		return controlResponse{Status: a.status()}
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
		info.Devices = append(info.Devices, deviceInfo{device.ID, device.Name, device.PairedAt, device.LastUsedAt})
	}
	a.mu.Unlock()

	info.Pairing = a.auth.PairingActive()
	if locked, err := a.screen.IsLocked(); err != nil {
		info.LockError = err.Error()
	} else {
		info.Locked = &locked
	}
	if info.PasswordNeeded {
		_, err := a.passwords.Load()
		info.PasswordSaved = err == nil
	}
	return info
}

// unpair removes a device by id or (case-insensitive) name.
func (a *Agent) unpair(which string) (PairedDevice, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var matches []int
	for i, device := range a.state.Devices {
		if device.ID == which || strings.EqualFold(device.Name, which) {
			matches = append(matches, i)
		}
	}
	if len(matches) == 0 {
		return PairedDevice{}, fmt.Errorf("no paired device called %q", which)
	}
	if len(matches) > 1 {
		return PairedDevice{}, fmt.Errorf("several devices are called %q; use the id from `faceunlock-agent status`", which)
	}
	i := matches[0]
	removed := a.state.Devices[i]
	a.state.Devices = append(a.state.Devices[:i], a.state.Devices[i+1:]...)
	return removed, a.state.save()
}

func callAgent(request controlRequest) (controlResponse, error) {
	conn, err := net.DialTimeout("unix", controlSocketPath(), 3*time.Second)
	if err != nil {
		return controlResponse{}, errors.New("the agent isn't running. Start it with `systemctl --user start faceunlock-agent` (or `faceunlock-agent run`)")
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

func platformName() string {
	if runtime.GOOS == "darwin" {
		return "macOS"
	}
	return runtime.GOOS
}
