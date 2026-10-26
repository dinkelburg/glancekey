package main

import (
	"errors"
	"testing"
)

func TestStateLockKeepsOneWriter(t *testing.T) {
	t.Setenv(envPrefix+"CONFIG_DIR", t.TempDir())
	first, err := lockState()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockState(); !errors.Is(err, errStateLocked) {
		t.Fatalf("second lock: %v", err)
	}
	first.Close()
	second, err := lockState()
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	second.Close()
}
