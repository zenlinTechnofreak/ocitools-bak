package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"github.com/opencontainers/specs"
)

func validateSeccomp(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec) error {
	if rspec.Linux.Seccomp.DefaultAction == specs.Action("SCMP_ACT_ALLOW") {
		for _, syscall := range rspec.Linux.Seccomp.Syscalls {
			if strings.EqualFold(syscall.Name, "getcwd") && syscall.Action == specs.Action("SCMP_ACT_ERRNO") {
				var stderr bytes.Buffer
				cmd := exec.Command("pwd")
				cmd.Stderr = &stderr
				err := cmd.Run()
				if err == nil {
					fmt.Errorf("Expecting error (negative return code);but exited cleanly!")
				}
				if !strings.EqualFold(stderr.String(), "pwd: getcwd: Operation not permitted") {
					return fmt.Errorf("stderr expected: \"pwd: getcwd: Operation not permitted\", actual: %v", stderr.String())
				}
			}
		}
	}
	return nil
}
