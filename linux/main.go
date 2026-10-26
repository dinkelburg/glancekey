// The agent unlocks this Linux desktop when you approve it with Face ID on your iPhone.
// It keeps an outgoing WebSocket to the relay, so it works on any network.
package main

import (
	"bufio"
	"context"
	"encoding/json"
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
	"text/tabwriter"
	"time"

	"github.com/mdp/qrterminal/v3"
)

// version is the release, set by the build scripts from MARKETING_VERSION in project.yml.
var version = "dev"

// usage is filled in from brand.go; tabwriter lines up the descriptions, however long the command's name is.
var usage = func() string {
	text := strings.NewReplacer("{agent}", agentCommand, "{ENV}", envPrefix).Replace(`{agent}: unlock this computer with Face ID on your iPhone.

Usage:
  {agent} install-service	Install and start the systemd user service
  {agent} set-password [--stdin]	Save your login password in the keyring (Omarchy lock screen)
  {agent} forget-password	Remove the saved password
  {agent} pair	Show a QR code to pair your iPhone
  {agent} status	Show the connection, lock screen and paired iPhones
  {agent} unpair <name-or-id>	Remove a paired iPhone
  {agent} run	Run the agent in the foreground (what the service does)

Approve sudo and polkit prompts on your iPhone (they fall back to the password if you don't):
  sudo {agent} enable-sudo	Install the checker, trust the paired iPhones, add the PAM lines
  sudo {agent} disable-sudo	Undo that
  {agent} pam [--timeout 30s]	The checker PAM runs as root (not for direct use)

Environment:
  {ENV}SCREEN=omarchy|hyprlock|logind|fake	Force a lock screen backend
  {ENV}RELAY=<url>	Use another relay (testing)
  {ENV}CONFIG_DIR=<dir>	Keep state somewhere else (testing)
`)
	var out strings.Builder
	columns := tabwriter.NewWriter(&out, 0, 0, 2, ' ', 0)
	columns.Write([]byte(text))
	columns.Flush()
	return out.String()
}()

func main() {
	log.SetFlags(0)
	if len(os.Args) > 1 && os.Args[1] == "pam" {
		os.Exit(runChecker(os.Args[2:]))
	}
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
			err = errors.New("usage: " + agentCommand + " unpair <name-or-id>")
		} else {
			_, err = callAgent(controlRequest{Command: "unpair", Argument: os.Args[2]})
		}
	case "set-password":
		err = cmdSetPassword(len(os.Args) > 2 && os.Args[2] == "--stdin")
	case "forget-password":
		err = keyringPasswords{}.Clear()
	case "install-service":
		err = cmdInstallService()
	case "enable-sudo":
		err = cmdEnableSudo(os.Args[2:])
	case "disable-sudo":
		err = cmdDisableSudo()
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
	log.Printf("%s agent %s on %s, lock screen: %s, relay: %s", appName, version, state.MachineName, screen.Name(), state.relayURL())

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
	fmt.Println("Scan this with your iPhone's Camera app (" + appName + " must be installed):")
	fmt.Println()
	qrterminal.GenerateHalfBlock(response.Invite, qrterminal.L, os.Stdout)
	fmt.Printf("\nOr paste this into the %s app:\n%s\n\n", appName, response.Invite)
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
					fmt.Printf("Paired %s. Unlock this computer from the %s app.\n", device.Name, appName)
					return nil
				}
			}
			return fmt.Errorf("the pairing code expired; run `%s pair` again", agentCommand)
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
			saved = "NOT saved; run `" + agentCommand + " set-password`"
		}
		fmt.Printf("Password:     %s\n", saved)
	}
	if len(s.Devices) == 0 {
		fmt.Println("iPhones:      none paired; run `" + agentCommand + " pair`")
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
	fmt.Printf("sudo:         %s\n", sudoApprovalStatus(s.Devices))
	return nil
}

// sudoApprovalStatus says whether sudo waits for the iPhone, and whether approvers.json is out of date.
func sudoApprovalStatus(devices []deviceInfo) string {
	data, err := os.ReadFile(approversPath)
	if err != nil {
		return "asks for your password (`sudo " + agentCommand + " enable-sudo` lets your iPhone approve it)"
	}
	var approvers Approvers
	if json.Unmarshal(data, &approvers) != nil {
		return "approvers.json is unreadable; run `sudo " + agentCommand + " enable-sudo` again"
	}
	for _, device := range devices {
		if approvers.find(device.ID) == nil {
			return fmt.Sprintf("%s can't approve yet; run `sudo %s enable-sudo` again", device.Name, agentCommand)
		}
	}
	return fmt.Sprintf("waits for your iPhone first (%d approver(s))", len(approvers.Devices))
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
	fmt.Println("Saved in your keyring. " + appName + " types it on the lock screen after you approve with Face ID.")
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
Description=%s agent (unlock with Face ID on your iPhone)
After=graphical-session.target
PartOf=graphical-session.target

[Service]
ExecStart=%s run
Restart=always
RestartSec=5

[Install]
WantedBy=graphical-session.target
`, appName, executable)
	if err := os.WriteFile(filepath.Join(unitDir, agentCommand+".service"), []byte(unit), 0o644); err != nil {
		return err
	}
	for _, args := range [][]string{{"--user", "daemon-reload"}, {"--user", "enable", "--now", agentCommand + ".service"}} {
		if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	fmt.Println("Installed and started. Logs: journalctl --user -u " + agentCommand + " -f")
	return nil
}
