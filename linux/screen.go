package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Screen is one way of locking and unlocking the desktop session.
type Screen interface {
	Name() string
	IsLocked() (bool, error)
	Lock() error
	// Unlock gets the lock screen to unlock. password is empty when NeedsPassword is false.
	Unlock(password string) error
	NeedsPassword() bool
	// Wake turns the displays on.
	Wake()
}

// fakeScreen pretends to lock and unlock. Used on non-Linux systems and with FACEUNLOCK_SCREEN=fake for testing.
type fakeScreen struct {
	mu     sync.Mutex
	locked bool
}

func (s *fakeScreen) Name() string { return "fake (testing only)" }

func (s *fakeScreen) IsLocked() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.locked, nil
}

func (s *fakeScreen) Lock() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.locked = true
	return nil
}

func (s *fakeScreen) Unlock(string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.locked = false
	return nil
}

func (s *fakeScreen) NeedsPassword() bool { return false }
func (s *fakeScreen) Wake()               {}

// run executes a command with an optional stdin and returns its stdout without the trailing newline.
// Errors include stderr but never stdin, which may hold the password.
func run(timeout time.Duration, stdin string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := strings.TrimSuffix(stdout.String(), "\n")
	if err != nil {
		if message := strings.TrimSpace(stderr.String()); message != "" {
			return out, fmt.Errorf("%s: %v: %s", name, err, message)
		}
		return out, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}
