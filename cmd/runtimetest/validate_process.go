package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/opencontainers/specs"
)

func validateProcess(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec) error {
	uid := os.Getuid()
	if uint32(uid) != spec.Process.User.UID {
		return fmt.Errorf("UID expected: %v, actual: %v", spec.Process.User.UID, uid)
	}
	gid := os.Getgid()
	if uint32(gid) != spec.Process.User.GID {
		return fmt.Errorf("GID expected: %v, actual: %v", spec.Process.User.GID, gid)
	}

	groups, err := os.Getgroups()
	if err != nil {
		return err
	}

	groupsMap := make(map[int]bool)
	for _, g := range groups {
		groupsMap[g] = true
	}

	for _, g := range spec.Process.User.AdditionalGids {
		if !groupsMap[int(g)] {
			return fmt.Errorf("Groups expected: %v, actual (should be superset): %v", spec.Process.User.AdditionalGids, groups)
		}
	}

	if spec.Process.Cwd != "" {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		if cwd != spec.Process.Cwd {
			return fmt.Errorf("Cwd expected: %v, actual: %v", spec.Process.Cwd, cwd)
		}
	}

	cmdlineBytes, err := ioutil.ReadFile("/proc/1/cmdline")
	if err != nil {
		return err
	}
	args := strings.Split(string(bytes.TrimSuffix(cmdlineBytes, []byte("\x00"))), "\x00")
	if len(args) != len(spec.Process.Args) {
		return fmt.Errorf("Process arguments expected: %v, actual: %v", len(args),len(spec.Process.Args))
	}
	for i, a := range args {
		if a != spec.Process.Args[i] {
			return fmt.Errorf("Process arguments expected: %v, actual: %v", a, spec.Process.Args[i])
		}
	}

	for _, env := range spec.Process.Env {
		parts := strings.Split(env, "=")
		key := parts[0]
		expectedValue := parts[1]
		actualValue := os.Getenv(key)
		if actualValue != expectedValue {
			return fmt.Errorf("Env %v expected: %v, actual: %v", expectedValue, actualValue)
		}
	}

	return nil
}
