package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"

	"golang.org/x/sys/unix"
)

// processInfo returns a process's arguments and environment (root can read any process's). kern.procargs2
// holds argc, the executable path, NULs up to a multiple of 8 bytes, then the arguments and the environment, all
// NUL-terminated. The arguments start exactly there: skipping every NUL instead would also skip an empty first
// argument and shift the rest, so the iPhone would show a different command than the one that runs.
func processInfo(pid int) ([]string, map[string]string, error) {
	buffer, err := procargs2(pid)
	if err != nil {
		return nil, nil, err
	}
	argc := int(binary.LittleEndian.Uint32(buffer[:4]))
	rest := buffer[4:]
	end := bytes.IndexByte(rest, 0)
	start := (end + 8) &^ 7
	if end < 0 || start > len(rest) || len(bytes.Trim(rest[end:start], "\x00")) > 0 {
		return nil, nil, errors.New("unexpected kern.procargs2")
	}
	parts := bytes.Split(rest[start:], []byte{0})
	if len(parts) < argc {
		return nil, nil, errors.New("short kern.procargs2")
	}
	var args []string
	env := map[string]string{}
	for i, part := range parts {
		if i < argc {
			args = append(args, string(part))
			continue
		}
		if len(part) == 0 {
			break
		}
		if name, value, ok := strings.Cut(string(part), "="); ok {
			env[name] = value
		}
	}
	return args, env, nil
}

// executableOf returns the program a process runs, the path kern.procargs2 starts with.
func executableOf(pid int) (string, error) {
	buffer, err := procargs2(pid)
	if err != nil {
		return "", err
	}
	path, _, _ := bytes.Cut(buffer[4:], []byte{0})
	return string(path), nil
}

func procargs2(pid int) ([]byte, error) {
	buffer, err := unix.SysctlRaw("kern.procargs2", pid)
	if err == nil && len(buffer) < 4 {
		err = errors.New("short kern.procargs2")
	}
	return buffer, err
}

// parentOf returns a process's parent and command name.
func parentOf(pid int) (int, string, error) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, "", err
	}
	name := info.Proc.P_comm[:]
	if end := bytes.IndexByte(name, 0); end >= 0 {
		name = name[:end]
	}
	return int(info.Eproc.Ppid), string(name), nil
}
