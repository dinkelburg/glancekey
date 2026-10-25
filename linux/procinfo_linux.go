package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
)

// processInfo returns a process's arguments and environment (root can read any process's).
func processInfo(pid int) ([]string, map[string]string, error) {
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil, nil, err
	}
	args := strings.Split(strings.TrimSuffix(string(cmdline), "\x00"), "\x00")
	env := map[string]string{}
	if environ, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid)); err == nil {
		for _, entry := range bytes.Split(environ, []byte{0}) {
			if name, value, ok := strings.Cut(string(entry), "="); ok {
				env[name] = value
			}
		}
	}
	return args, env, nil
}

// parentOf returns a process's parent and command name, from /proc/<pid>/stat, which (unlike environ) is
// readable for every process.
func parentOf(pid int) (int, string, error) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, "", err
	}
	// pid (comm) state ppid …; comm may contain spaces and parentheses.
	open, close := bytes.IndexByte(stat, '('), bytes.LastIndexByte(stat, ')')
	if open < 0 || close < open {
		return 0, "", fmt.Errorf("unexpected /proc/%d/stat", pid)
	}
	fields := strings.Fields(string(stat[close+1:]))
	if len(fields) < 2 {
		return 0, "", fmt.Errorf("unexpected /proc/%d/stat", pid)
	}
	var ppid int
	if _, err := fmt.Sscan(fields[1], &ppid); err != nil {
		return 0, "", err
	}
	return ppid, string(stat[open+1 : close]), nil
}
