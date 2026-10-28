//go:build !linux && !darwin

package main

import "errors"

func processInfo(int) ([]string, map[string]string, error) {
	return nil, nil, errors.New("not supported on this system")
}

func executableOf(int) (string, error) {
	return "", errors.New("not supported on this system")
}

func parentOf(int) (int, string, error) {
	return 0, "", errors.New("not supported on this system")
}
