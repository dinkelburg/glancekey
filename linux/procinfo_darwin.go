package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"

	"golang.org/x/sys/unix"
)

// processInfo returns a process's arguments and environment (root can read any process's). kern.procargs2
// holds argc, the executable path, padding, then the arguments and the environment, all NUL-terminated.
func processInfo(pid int) ([]string, map[string]string, error) {
	buffer, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return nil, nil, err
	}
	if len(buffer) < 4 {
		return nil, nil, errors.New("short kern.procargs2")
	}
	argc := int(binary.LittleEndian.Uint32(buffer[:4]))
	rest := buffer[4:]
	if end := bytes.IndexByte(rest, 0); end >= 0 {
		rest = rest[end:]
	}
	rest = bytes.TrimLeft(rest, "\x00")
	parts := bytes.Split(rest, []byte{0})
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
