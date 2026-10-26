package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// State is the agent's identity and paired iPhones, in ~/.config/<appID>/agent.json (mode 0600).
type State struct {
	MachineID   string `json:"machineId"`
	MachineName string `json:"machineName"`
	// AgentSecret claims this machine id on the relay, so nobody else can take its place there.
	AgentSecret string         `json:"agentSecret"`
	Relay       string         `json:"relay"`
	Devices     []PairedDevice `json:"devices"`
	// SealedPasswords is the login password sealed to each paired iPhone's password key, by device id (seal.go).
	SealedPasswords map[string]SealedPassword `json:"sealedPasswords,omitempty"`
}

func configDir() string {
	if dir := os.Getenv(envPrefix + "CONFIG_DIR"); dir != "" {
		return dir
	}
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, appID)
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", appID)
}

func statePath() string {
	return filepath.Join(configDir(), "agent.json")
}

var errStateLocked = errors.New("state is in use by another process")

// lockState keeps the state to one process: the running agent holds the lock for as long as it runs, so a second
// agent, or a password command that found no control socket, can't write agent.json behind its back. The lock goes
// when the returned file is closed or the process exits.
func lockState() (*os.File, error) {
	if err := os.MkdirAll(configDir(), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(configDir(), "agent.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, errStateLocked
	}
	return file, nil
}

// loadState reads the state file, creating a fresh identity on first run.
func loadState() (*State, error) {
	data, err := os.ReadFile(statePath())
	if errors.Is(err, fs.ErrNotExist) {
		name, _ := os.Hostname()
		state := &State{MachineID: randomUUID(), MachineName: name, AgentSecret: randomToken(32), Relay: defaultRelay}
		return state, state.save()
	}
	if err != nil {
		return nil, err
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

// relayURL lets <envPrefix>RELAY point a test run at a local relay without touching the saved state.
func (s *State) relayURL() string {
	if relay := os.Getenv(envPrefix + "RELAY"); relay != "" {
		return relay
	}
	return s.Relay
}

func (s *State) save() error {
	if err := os.MkdirAll(configDir(), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	// Synced before the rename, and the folder after it: once a sealed copy is saved, the keyring's plain copy may be
	// removed, so a crash mustn't bring back an older agent.json.
	temp := statePath() + ".tmp"
	file, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temp, statePath()); err != nil {
		return err
	}
	if dir, err := os.Open(configDir()); err == nil {
		dir.Sync()
		dir.Close()
	}
	return nil
}
