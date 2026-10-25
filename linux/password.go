package main

import (
	"errors"
	"os"
	"os/exec"
	"os/user"
	"time"
)

type passwordCheck int

const (
	checkUnknown passwordCheck = iota
	checkCorrect
	checkWrong
)

var errNoPassword = errors.New("no password saved")

type PasswordStore interface {
	Load() (string, error)
	Save(password string) error
	Clear() error
	Check(password string) passwordCheck
}

// keyringPasswords keeps the login password in the Secret Service keyring (GNOME Keyring on Omarchy), which
// your login unlocks. It's checked with unix_chkpwd, PAM's own helper, before it's ever typed.
type keyringPasswords struct{}

var keyringAttributes = []string{"service", appID, "account", username()}

func (keyringPasswords) Load() (string, error) {
	out, err := run(10*time.Second, "", "secret-tool", append([]string{"lookup"}, keyringAttributes...)...)
	// Nothing stored: secret-tool prints nothing and exits 0 or 1, depending on the version.
	var exit *exec.ExitError
	nothingStored := err == nil || (errors.As(err, &exit) && exit.ExitCode() == 1)
	if out == "" && nothingStored {
		return "", errNoPassword
	}
	return out, err
}

func (keyringPasswords) Save(password string) error {
	args := append([]string{"store", "--label=" + appName + ": login password"}, keyringAttributes...)
	_, err := run(10*time.Second, password, "secret-tool", args...)
	return err
}

func (keyringPasswords) Clear() error {
	_, err := run(10*time.Second, "", "secret-tool", append([]string{"clear"}, keyringAttributes...)...)
	return err
}

// Check asks unix_chkpwd, which pam_unix uses to let you verify your own password. It reads the
// password NUL-terminated from a pipe.
func (keyringPasswords) Check(password string) passwordCheck {
	for _, helper := range []string{"/usr/bin/unix_chkpwd", "/usr/sbin/unix_chkpwd", "/sbin/unix_chkpwd"} {
		if _, err := os.Stat(helper); err != nil {
			continue
		}
		_, err := run(10*time.Second, password+"\x00", helper, username(), "nonull")
		var exit *exec.ExitError
		switch {
		case err == nil:
			return checkCorrect
		case errors.As(err, &exit) && exit.ExitCode() == 7: // PAM_AUTH_ERR
			return checkWrong
		default:
			return checkUnknown
		}
	}
	return checkUnknown
}

func username() string {
	if current, err := user.Current(); err == nil {
		return current.Username
	}
	return os.Getenv("USER")
}
