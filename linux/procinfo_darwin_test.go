package main

import (
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"
)

// TestProcessInfoHelper is the process TestProcessInfoKeepsEmptyFirstArgument reads.
func TestProcessInfoHelper(t *testing.T) {
	if os.Getenv("PROCINFO_HELPER") == "" {
		t.Skip("only run by TestProcessInfoKeepsEmptyFirstArgument")
	}
	time.Sleep(5 * time.Second)
}

// An empty first argument has to stay, or every argument shifts and the iPhone shows another command than sudo runs.
func TestProcessInfoKeepsEmptyFirstArgument(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, first := range []string{"", "sudo", "a-much-longer-first-argument"} {
		cmd := exec.Command(executable)
		cmd.Args = []string{first, "-test.run=^TestProcessInfoHelper$", "pacman"}
		cmd.Env = []string{"PROCINFO_HELPER=1", "--needed"}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		var args []string
		var env map[string]string
		for i := 0; i < 50; i++ {
			time.Sleep(20 * time.Millisecond)
			if args, env, err = processInfo(cmd.Process.Pid); err == nil && len(args) == len(cmd.Args) {
				break
			}
		}
		path, pathErr := executableOf(cmd.Process.Pid)
		cmd.Process.Kill()
		cmd.Wait()
		if err != nil || !reflect.DeepEqual(args, cmd.Args) || env["PROCINFO_HELPER"] != "1" {
			t.Fatalf("first argument %q: got %q, %v, %v", first, args, env, err)
		}
		if pathErr != nil || path != executable {
			t.Fatalf("executable: %q, %v (want %q)", path, pathErr, executable)
		}
	}
}
