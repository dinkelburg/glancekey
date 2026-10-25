package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

// `sudo <agent> enable-sudo` lets sudo (and polkit on Linux) wait for your iPhone before asking for the
// password. It copies this binary to a root-owned place, saves the paired iPhones as approvers.json and adds one
// `auth sufficient` line to the PAM config. On the Mac, scripts/enable-mac-sudo.sh runs it with the PAM module.

const (
	macModulePath = "/usr/local/lib/pam/pam_" + appID + ".so.2"
	pamMarker     = "# " + appName + ": approve with Face ID on your iPhone first (undo: " + agentCommand + " disable-sudo)"
)

var (
	pamDir = "/etc/pam.d"
	// Newer packages (polkit on Arch and Debian) ship their PAM config here and only read /etc/pam.d/<service>
	// as an override.
	vendorPAMDirs    = []string{"/usr/lib/pam.d", "/usr/share/pam.d"}
	linuxPAMServices = []string{"sudo", "polkit-1"}
)

// createdMarker starts an override enable-sudo created from a vendor file; disable-sudo deletes such files.
const createdMarker = "# " + appName + " created this file from "

func cmdEnableSudo(args []string) error {
	flags := flag.NewFlagSet("enable-sudo", flag.ContinueOnError)
	module := flags.String("module", "", "macOS: the built PAM module (Mac/PAM)")
	pamCheck := flags.String("pam-check", "", "macOS: the built pam-check tool, to test the module before sudo uses it")
	if err := flags.Parse(args); err != nil {
		return err
	}
	account, err := sudoingUser()
	if err != nil {
		return err
	}
	approvers, err := askApprovers(agentSocketFor(account))
	if err != nil {
		return fmt.Errorf("couldn't get your paired iPhones (%v). Is the %s agent or Mac app running for %s?", err, appName, account.Username)
	}
	if len(approvers.Devices) == 0 {
		return errors.New("no iPhone is paired yet; pair one first")
	}

	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if err := installFile(executable, checkerInstallPath, 0o755); err != nil {
		return err
	}
	if err := checkTree(checkerInstallPath); err != nil {
		return fmt.Errorf("sudo would run the checker from an unsafe place: %w", err)
	}
	data, _ := json.MarshalIndent(approvers, "", "  ")
	if err := writeFile(approversPath, data, 0o644); err != nil {
		return err
	}
	if out, err := exec.Command(checkerInstallPath, "pam", "--check").CombinedOutput(); err != nil {
		return fmt.Errorf("the installed checker doesn't work: %v: %s", err, out)
	}

	switch runtime.GOOS {
	case "linux":
		err = enableLinuxPAM()
	case "darwin":
		err = enableMacPAM(*module, *pamCheck, account.Username)
	default:
		err = errors.New("only Linux and macOS are supported")
	}
	if err != nil {
		return err
	}

	var names []string
	for _, device := range approvers.Devices {
		names = append(names, device.Name)
	}
	fmt.Printf("Done. sudo now waits for %s first; open %s to approve, or wait for the password prompt.\n", strings.Join(names, ", "), appName)
	fmt.Printf("After pairing another iPhone or updating %s, run this again. To undo: sudo %s disable-sudo\n", appName, agentCommand)
	return nil
}

func cmdDisableSudo() error {
	if os.Geteuid() != 0 {
		return errors.New("run it with sudo: sudo " + agentCommand + " disable-sudo")
	}
	files := []string{"/etc/pam.d/sudo_local"}
	if runtime.GOOS != "darwin" {
		files = nil
		for _, service := range linuxPAMServices {
			files = append(files, filepath.Join(pamDir, service))
		}
	}
	if err := removePAMConfig(files); err != nil {
		return err
	}
	for _, path := range []string{approversPath, filepath.Dir(approversPath), checkerInstallPath, filepath.Dir(checkerInstallPath), macModulePath} {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	fmt.Println("Done. sudo asks for your password as before.")
	return nil
}

// removePAMConfig takes the lines enable-sudo added out again, and deletes the overrides it created.
func removePAMConfig(files []string) error {
	for _, file := range files {
		data, err := os.ReadFile(file)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if strings.HasPrefix(string(data), createdMarker) {
			if err := os.Remove(file); err != nil {
				return err
			}
			fmt.Println("Removed", file)
			continue
		}
		updated := removePAMLines(string(data))
		if updated == string(data) {
			continue
		}
		if runtime.GOOS == "darwin" && strings.TrimSpace(stripComments(updated)) == "" {
			err = os.Remove(file)
		} else {
			err = writeFile(file, []byte(updated), 0o644)
		}
		if err != nil {
			return err
		}
		fmt.Println("Updated", file)
	}
	return nil
}

// sudoingUser is the account that ran `sudo <agent> …`.
func sudoingUser() (*user.User, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("run it with sudo: sudo " + agentCommand + " enable-sudo")
	}
	name := os.Getenv("SUDO_USER")
	if name == "" || name == "root" {
		return nil, errors.New("run it with sudo from your own account")
	}
	return user.Lookup(name)
}

func enableLinuxPAM() error {
	if findPAMExec() == "" {
		return errors.New("pam_exec.so isn't installed")
	}
	return addLinuxPAMLines("auth       sufficient   pam_exec.so quiet stdout seteuid " + checkerInstallPath + " pam")
}

func addLinuxPAMLines(line string) error {
	for i, service := range linuxPAMServices {
		file := filepath.Join(pamDir, service)
		data, err := os.ReadFile(file)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			vendor := vendorPAMFile(service)
			if vendor == "" {
				if i == 0 {
					return fmt.Errorf("found no PAM config for %s", service)
				}
				continue // no polkit
			}
			if data, err = os.ReadFile(vendor); err != nil {
				return err
			}
			data = []byte(createdMarker + vendor + "; disable-sudo removes it again. Run enable-sudo again after\n" +
				"# updates of that package, since this file replaces the package's version.\n" + string(data))
		case err != nil:
			return err
		case !strings.HasPrefix(string(data), createdMarker):
			if err := backUp(file, data); err != nil {
				return err
			}
		}
		if err := writeFile(file, []byte(addPAMLine(string(data), line)), 0o644); err != nil {
			return err
		}
		fmt.Println("Updated", file)
	}
	return nil
}

func vendorPAMFile(service string) string {
	for _, dir := range vendorPAMDirs {
		path := filepath.Join(dir, service)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func findPAMExec() string {
	patterns := []string{"/usr/lib/security/pam_exec.so", "/lib/security/pam_exec.so", "/usr/lib64/security/pam_exec.so",
		"/lib64/security/pam_exec.so", "/usr/lib/*/security/pam_exec.so", "/lib/*/security/pam_exec.so"}
	for _, pattern := range patterns {
		if matches, _ := filepath.Glob(pattern); len(matches) > 0 {
			return matches[0]
		}
	}
	return ""
}

// enableMacPAM installs the PAM module, checks that PAM can load it and run the checker (a module that fails to
// load would break sudo completely), and only then adds it to /etc/pam.d/sudo_local, which survives macOS updates.
func enableMacPAM(module, pamCheck, username string) error {
	if module == "" || pamCheck == "" {
		return errors.New("on a Mac, run scripts/enable-mac-sudo.sh, which builds the PAM module")
	}
	if sudo, err := os.ReadFile("/etc/pam.d/sudo"); err != nil || !strings.Contains(string(sudo), "sudo_local") {
		return errors.New("this macOS doesn't read /etc/pam.d/sudo_local (needs macOS 14 or later)")
	}
	if err := installFile(module, macModulePath, 0o755); err != nil {
		return err
	}
	if err := checkTree(macModulePath); err != nil {
		return fmt.Errorf("sudo would load the module from an unsafe place: %w", err)
	}
	checkService := "/etc/pam.d/" + appID + "-check"
	if err := writeFile(checkService, []byte("auth       required       "+macModulePath+" "+checkerInstallPath+" --check\n"), 0o644); err != nil {
		return err
	}
	out, err := exec.Command(pamCheck, appID+"-check", username).CombinedOutput()
	os.Remove(checkService)
	if err != nil {
		return fmt.Errorf("PAM couldn't use the module, so sudo_local wasn't changed: %v: %s", err, out)
	}

	file := "/etc/pam.d/sudo_local"
	data, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		data = []byte("# sudo_local: local config file which survives system update and is included for sudo\n")
	} else if err != nil {
		return err
	} else if err := backUp(file, data); err != nil {
		return err
	}
	line := "auth       sufficient     " + macModulePath + " " + checkerInstallPath
	if err := writeFile(file, []byte(addPAMLine(string(data), line)), 0o444); err != nil {
		return err
	}
	fmt.Println("Updated", file)
	return nil
}

// addPAMLine puts the checker's line before the first auth line (or Debian's @include common-auth), replacing
// an earlier one, so it runs before the password prompt.
func addPAMLine(config, line string) string {
	lines := strings.Split(removePAMLines(config), "\n")
	at := -1
	for i, l := range lines {
		fields := strings.Fields(l)
		if len(fields) > 0 && (strings.TrimPrefix(fields[0], "-") == "auth" || (fields[0] == "@include" && len(fields) > 1 && strings.Contains(fields[1], "auth"))) {
			at = i
			break
		}
	}
	if at < 0 {
		// No auth lines (e.g. a new sudo_local): add after the leading comments.
		at = 0
		for at < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[at]), "#") {
			at++
		}
	}
	added := append([]string{pamMarker, line}, lines[at:]...)
	result := strings.Join(append(lines[:at:at], added...), "\n")
	if !strings.HasSuffix(result, "\n") {
		result += "\n"
	}
	return result
}

func removePAMLines(config string) string {
	var kept []string
	for _, l := range strings.Split(config, "\n") {
		if l == pamMarker || strings.Contains(l, checkerInstallPath) || strings.Contains(l, "pam_"+appID+".so") {
			continue
		}
		kept = append(kept, l)
	}
	return strings.Join(kept, "\n")
}

func stripComments(config string) string {
	var kept []string
	for _, l := range strings.Split(config, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "#") {
			kept = append(kept, l)
		}
	}
	return strings.Join(kept, "\n")
}

func backUp(file string, data []byte) error {
	backup := file + ".before-" + appID
	if _, err := os.Stat(backup); err == nil {
		return nil
	}
	return os.WriteFile(backup, data, 0o644)
}

func installFile(from, to string, mode os.FileMode) error {
	data, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	return writeFile(to, data, mode)
}

// writeFile replaces path atomically with a root-owned file (as this runs as root) in a root-owned folder.
func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temp := path + "." + appID + "-tmp"
	if err := os.WriteFile(temp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(temp, mode); err != nil {
		os.Remove(temp)
		return err
	}
	return os.Rename(temp, path)
}
