//go:build !linux

package main

// Off Linux the agent only runs for testing, with a pretend lock screen.
func detectScreen() Screen { return &fakeScreen{} }

func prepareSessionEnv() {}
