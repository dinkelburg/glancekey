// faceunlock-agent unlocks this Linux desktop when you approve it with Face ID on your iPhone.
// It keeps an outgoing WebSocket to the FaceUnlock relay, so it works on any network.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mdp/qrterminal/v3"
)

const version = "1.0"

const usage = `faceunlock-agent: unlock this computer with Face ID on your iPhone.

Usage:
  faceunlock-agent install-service      Install and start the systemd user service
  faceunlock-agent set-password [--stdin]
                                        Save your login password in the keyring (Omarchy lock screen)
  faceunlock-agent forget-password      Remove the saved password
  faceunlock-agent pair                 Show a QR code to pair your iPhone
  faceunlock-agent status               Show the connection, lock screen and paired iPhones
  faceunlock-agent unpair <name-or-id>  Remove a paired iPhone
  faceunlock-agent run                  Run the agent in the foreground (what the service does)

Environment:
  FACEUNLOCK_SCREEN=omarchy|hyprlock|logind|fake   Force a lock screen backend
  FACEUNLOCK_RELAY=<url>                           Use another relay (testing)
  FACEUNLOCK_CONFIG_DIR=<dir>                      Keep state somewhere else (testing)
`

func main() {
	log.SetFlags(0)
	prepareSessionEnv()
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(64)
	}

	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun()
	case "pair":
		err = cmdPair()
	case "status", "devices":
		err = cmdStatus()
	case "unpair":
		if len(os.Args) != 3 {
			err = errors.New("usage: faceunlock-agent unpair <name-or-id>")
		} else {
			_, err = callAgent(controlRequest{Command: "unpair", Argument: os.Args[2]})
		}
	case "set-password":
		err = cmdSetPassword(len(os.Args) > 2 && os.Args[2] == "--stdin")
	case "forget-password":
		err = keyringPasswords{}.Clear()
	case "install-service":
		err = cmdInstallService()
	case "version", "--version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(64)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func cmdRun() error {
	state, err := loadState()
	if err != nil {
		return fmt.Errorf("reading %s: %w", statePath(), err)
	}
	screen := detectScreen()
	agent := newAgent(state, screen, keyringPasswords{})
	log.Printf("FaceUnlock agent %s on %s, lock screen: %s, relay: %s", version, state.MachineName, screen.Name(), state.relayURL())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		if err := agent.serveControl(ctx); err != nil {
			log.Printf("Control socket unavailable: %v", err)
		}
	}()
	agent.runRelay(ctx)
	return nil
}

func cmdPair() error {
	before, err := callAgent(controlRequest{Command: "status"})
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, device := range before.Status.Devices {
		known[device.ID] = true
	}

	response, err := callAgent(controlRequest{Command: "pair"})
	if err != nil {
		return err
	}
	fmt.Println("Scan this with your iPhone's Camera app (FaceUnlock must be installed):")
	fmt.Println()
	qrterminal.GenerateHalfBlock(response.Invite, qrterminal.L, os.Stdout)
	fmt.Printf("\nOr paste this into the FaceUnlock app:\n%s\n\n", response.Invite)
	fmt.Printf("Waiting for your iPhone until %s. Press Ctrl-C to cancel.\n", response.Expires.Local().Format("15:04"))

	interrupted := make(chan os.Signal, 1)
	signal.Notify(interrupted, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(interrupted)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-interrupted:
			callAgent(controlRequest{Command: "cancel-pair"})
			return errors.New("cancelled")
		case <-ticker.C:
			now, err := callAgent(controlRequest{Command: "status"})
			if err != nil {
				return err
			}
			if now.Status.Pairing {
				continue
			}
			for _, device := range now.Status.Devices {
				if !known[device.ID] {
					fmt.Printf("Paired %s. Unlock this computer from the FaceUnlock app.\n", device.Name)
					return nil
				}
			}
			return errors.New("the pairing code expired; run `faceunlock-agent pair` again")
		}
	}
}

func cmdStatus() error {
	response, err := callAgent(controlRequest{Command: "status"})
	if err != nil {
		return err
	}
	s := response.Status
	fmt.Printf("Computer:     %s (%s)\n", s.MachineName, s.MachineID)
	fmt.Printf("Relay:        %s, %s\n", s.Relay, s.RelayStatus)
	switch {
	case s.LockError != "":
		fmt.Printf("Lock screen:  %s, error: %s\n", s.Screen, s.LockError)
	case *s.Locked:
		fmt.Printf("Lock screen:  %s, locked\n", s.Screen)
	default:
		fmt.Printf("Lock screen:  %s, unlocked\n", s.Screen)
	}
	if s.PasswordNeeded {
		saved := "saved"
		if !s.PasswordSaved {
			saved = "NOT saved; run `faceunlock-agent set-password`"
		}
		fmt.Printf("Password:     %s\n", saved)
	}
	if len(s.Devices) == 0 {
		fmt.Println("iPhones:      none paired; run `faceunlock-agent pair`")
	}
	for i, device := range s.Devices {
		label := "iPhones:     "
		if i > 0 {
			label = "             "
		}
		used := "never used"
		if device.LastUsedAt != nil {
			used = "last used " + device.LastUsedAt.Local().Format("2 Jan 15:04")
		}
		fmt.Printf("%s %s (%s, %s)\n", label, device.Name, device.ID, used)
	}
	return nil
}

func cmdSetPassword(fromStdin bool) error {
	var password string
	var err error
	if fromStdin {
		data, readErr := io.ReadAll(os.Stdin)
		password, err = strings.TrimSuffix(string(data), "\n"), readErr
	} else {
		password, err = readPassword(fmt.Sprintf("Login password for %s: ", username()))
	}
	if err != nil {
		return err
	}
	if password == "" {
		return errors.New("empty password")
	}
	passwords := keyringPasswords{}
	switch passwords.Check(password) {
	case checkWrong:
		return fmt.Errorf("that isn't the login password for %s", username())
	case checkUnknown:
		fmt.Println("Couldn't verify the password here; saving it anyway.")
	}
	if err := passwords.Save(password); err != nil {
		return fmt.Errorf("saving to the keyring: %w", err)
	}
	fmt.Println("Saved in your keyring. FaceUnlock types it on the lock screen after you approve with Face ID.")
	return nil
}

// readPassword reads a line from the terminal with echo off.
func readPassword(prompt string) (string, error) {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return "", errors.New("no terminal; use --stdin")
	}
	defer tty.Close()
	fmt.Fprint(os.Stderr, prompt)
	setEcho := func(on string) {
		cmd := exec.Command("stty", on)
		cmd.Stdin = tty
		cmd.Run()
	}
	setEcho("-echo")
	defer setEcho("echo")
	line, err := bufio.NewReader(tty).ReadString('\n')
	fmt.Fprintln(os.Stderr)
	return strings.TrimRight(line, "\r\n"), err
}

func cmdInstallService() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if executable, err = filepath.EvalSymlinks(executable); err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		return err
	}
	unit := fmt.Sprintf(`[Unit]
Description=FaceUnlock agent (unlock with Face ID on your iPhone)
After=graphical-session.target
PartOf=graphical-session.target

[Service]
ExecStart=%s run
Restart=always
RestartSec=5

[Install]
WantedBy=graphical-session.target
`, executable)
	if err := os.WriteFile(filepath.Join(unitDir, "faceunlock-agent.service"), []byte(unit), 0o644); err != nil {
		return err
	}
	for _, args := range [][]string{{"--user", "daemon-reload"}, {"--user", "enable", "--now", "faceunlock-agent.service"}} {
		if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	fmt.Println("Installed and started. Logs: journalctl --user -u faceunlock-agent -f")
	return nil
}
