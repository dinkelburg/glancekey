//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// detectScreen picks the lock screen backend. FACEUNLOCK_SCREEN=omarchy|hyprlock|logind|fake overrides it.
func detectScreen() Screen {
	switch os.Getenv("FACEUNLOCK_SCREEN") {
	case "fake":
		return &fakeScreen{}
	case "omarchy":
		return omarchyScreen{}
	case "hyprlock":
		return hyprlockScreen{}
	case "logind":
		return logindScreen{}
	}
	if _, err := exec.LookPath("omarchy-shell"); err == nil {
		return omarchyScreen{}
	}
	if _, err := exec.LookPath("hyprlock"); err == nil {
		return hyprlockScreen{}
	}
	return logindScreen{}
}

// prepareSessionEnv fills in the Wayland and Omarchy session variables a systemd user service may lack.
func prepareSessionEnv() {
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		runtimeDir = fmt.Sprintf("/run/user/%d", os.Getuid())
		os.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	}
	if display := os.Getenv("WAYLAND_DISPLAY"); display == "" || !exists(socketPath(runtimeDir, display)) {
		if socket := newest(filepath.Join(runtimeDir, "wayland-[0-9]*"), func(p string) bool { return !strings.HasSuffix(p, ".lock") }); socket != "" {
			os.Setenv("WAYLAND_DISPLAY", filepath.Base(socket))
		}
	}
	if os.Getenv("HYPRLAND_INSTANCE_SIGNATURE") == "" {
		if instance := newest(filepath.Join(runtimeDir, "hypr", "*"), nil); instance != "" {
			os.Setenv("HYPRLAND_INSTANCE_SIGNATURE", filepath.Base(instance))
		}
	}
	home, _ := os.UserHomeDir()
	if os.Getenv("OMARCHY_PATH") == "" {
		for _, dir := range []string{"/usr/share/omarchy", filepath.Join(home, ".local/share/omarchy")} {
			if exists(filepath.Join(dir, "bin")) {
				os.Setenv("OMARCHY_PATH", dir)
				break
			}
		}
	}
	path := os.Getenv("PATH")
	for _, dir := range []string{filepath.Join(os.Getenv("OMARCHY_PATH"), "bin"), filepath.Join(home, ".local/bin"), "/usr/local/bin", "/usr/bin"} {
		if exists(dir) && !strings.Contains(":"+path+":", ":"+dir+":") {
			path += ":" + dir
		}
	}
	os.Setenv("PATH", strings.TrimPrefix(path, ":"))
}

// omarchyScreen drives Omarchy's own Quickshell lock screen. It deliberately has no unlock call, so the
// agent types the password into it with wtype, the same way you would.
type omarchyScreen struct{}

func (omarchyScreen) Name() string { return "Omarchy lock screen" }

func (omarchyScreen) IsLocked() (bool, error) {
	out, err := run(3*time.Second, "", "omarchy-shell", "lock", "isLocked")
	if err != nil {
		return false, err
	}
	switch out {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("unexpected answer from omarchy-shell: %q", out)
}

func (omarchyScreen) Lock() error {
	if _, err := exec.LookPath("omarchy-system-lock"); err == nil {
		_, err := run(15*time.Second, "", "omarchy-system-lock")
		return err
	}
	out, err := run(3*time.Second, "", "omarchy-shell", "lock", "lock")
	if err == nil && out != "ok" {
		err = fmt.Errorf("omarchy-shell lock lock: %s", out)
	}
	return err
}

func (s omarchyScreen) Unlock(password string) error {
	return typePassword(password, s.IsLocked)
}

func (omarchyScreen) NeedsPassword() bool { return true }
func (omarchyScreen) Wake()               { wakeDisplays() }

// hyprlockScreen is for Hyprland setups that use hyprlock, which unlocks on SIGUSR1.
type hyprlockScreen struct{}

func (hyprlockScreen) Name() string { return "hyprlock" }

func (hyprlockScreen) IsLocked() (bool, error) {
	_, err := run(3*time.Second, "", "pgrep", "-x", "-u", strconv.Itoa(os.Getuid()), "hyprlock")
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return false, nil
	}
	return err == nil, err
}

func (hyprlockScreen) Lock() error {
	_, err := run(5*time.Second, "", "hyprctl", "dispatch", "exec", "pidof hyprlock || hyprlock")
	return err
}

func (hyprlockScreen) Unlock(string) error {
	wakeDisplays()
	_, err := run(3*time.Second, "", "pkill", "-USR1", "-x", "-u", strconv.Itoa(os.Getuid()), "hyprlock")
	return err
}

func (hyprlockScreen) NeedsPassword() bool { return false }
func (hyprlockScreen) Wake()               { wakeDisplays() }

// logindScreen uses systemd-logind's lock/unlock, which GNOME and KDE Plasma honour.
type logindScreen struct{}

func (logindScreen) Name() string { return "systemd-logind (GNOME, KDE)" }

func (logindScreen) session() (string, error) {
	if id := os.Getenv("XDG_SESSION_ID"); id != "" {
		return id, nil
	}
	id, err := run(3*time.Second, "", "loginctl", "show-user", strconv.Itoa(os.Getuid()), "-p", "Display", "--value")
	if err == nil && id == "" {
		err = errors.New("no graphical session found")
	}
	return id, err
}

func (s logindScreen) IsLocked() (bool, error) {
	id, err := s.session()
	if err != nil {
		return false, err
	}
	out, err := run(3*time.Second, "", "loginctl", "show-session", id, "-p", "LockedHint", "--value")
	return out == "yes", err
}

func (s logindScreen) Lock() error {
	id, err := s.session()
	if err == nil {
		_, err = run(5*time.Second, "", "loginctl", "lock-session", id)
	}
	return err
}

func (s logindScreen) Unlock(string) error {
	id, err := s.session()
	if err == nil {
		_, err = run(5*time.Second, "", "loginctl", "unlock-session", id)
	}
	return err
}

func (logindScreen) NeedsPassword() bool { return false }
func (logindScreen) Wake()               {}

// typePassword clears the lock screen's field (Escape) and types the password with wtype, one character
// at a time over stdin so it never shows up in a process list. It rechecks the lock before every character
// and before Return, so if someone unlocks by hand at the same moment, at most one character can reach the
// app that gets focus, and the password is never submitted there.
func typePassword(password string, isLocked func() (bool, error)) error {
	if _, err := exec.LookPath("wtype"); err != nil {
		return errors.New("wtype isn't installed (sudo pacman -S wtype)")
	}
	wakeDisplays()
	time.Sleep(700 * time.Millisecond)

	stillLocked := func() (bool, error) {
		locked, err := isLocked()
		return err == nil && locked, err
	}
	if locked, err := stillLocked(); !locked {
		return err
	}
	if _, err := run(3*time.Second, "", "wtype", "-k", "Escape"); err != nil {
		return err
	}
	for _, character := range password {
		if locked, err := stillLocked(); !locked {
			return err
		}
		if _, err := run(3*time.Second, string(character), "wtype", "-"); err != nil {
			return err
		}
	}
	if locked, err := stillLocked(); !locked {
		return err
	}
	_, err := run(3*time.Second, "", "wtype", "-k", "Return")
	return err
}

func wakeDisplays() {
	run(3*time.Second, "", "hyprctl", "dispatch", "dpms", "on")
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func socketPath(runtimeDir, display string) string {
	if filepath.IsAbs(display) {
		return display
	}
	return filepath.Join(runtimeDir, display)
}

// newest returns the most recently modified match of pattern that passes keep.
func newest(pattern string, keep func(string) bool) string {
	matches, _ := filepath.Glob(pattern)
	type entry struct {
		path string
		time time.Time
	}
	var entries []entry
	for _, match := range matches {
		if info, err := os.Stat(match); err == nil && (keep == nil || keep(match)) {
			entries = append(entries, entry{match, info.ModTime()})
		}
	}
	if len(entries) == 0 {
		return ""
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].time.After(entries[j].time) })
	return entries[0].path
}
