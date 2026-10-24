package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// State is the agent's identity and paired iPhones, in ~/.config/faceunlock/agent.json (mode 0600).
type State struct {
	MachineID   string `json:"machineId"`
	MachineName string `json:"machineName"`
	// AgentSecret claims this machine id on the relay, so nobody else can take its place there.
	AgentSecret string         `json:"agentSecret"`
	Relay       string         `json:"relay"`
	Devices     []PairedDevice `json:"devices"`
}

func configDir() string {
	if dir := os.Getenv("FACEUNLOCK_CONFIG_DIR"); dir != "" {
		return dir
	}
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "faceunlock")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "faceunlock")
}

func statePath() string {
	return filepath.Join(configDir(), "agent.json")
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

// relayURL lets FACEUNLOCK_RELAY point a test run at a local relay without touching the saved state.
func (s *State) relayURL() string {
	if relay := os.Getenv("FACEUNLOCK_RELAY"); relay != "" {
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
	temp := statePath() + ".tmp"
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temp, statePath())
}
