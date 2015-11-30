package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"github.com/opencontainers/specs"
)

func validateSelinux(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec) error {
	if !strings.EqualFold(rspec.Linux.SelinuxProcessLabel, "") {
		var outbytes bytes.Buffer
		selinuxlable := rspec.Linux.SelinuxProcessLabel
		cmd := exec.Command("ps", "-efZ")
		cmd.Stdout = &outbytes
		if err := cmd.Run(); err != nil {
			return err
		}
		stdout := outbytes.String()
		lines := strings.Split(stdout, "\n")
		for _, line := range lines {
			cols := strings.Fields(line)
			if len(cols) == 9 {
				break
			}
			if strings.EqualFold(cols[2], "1") {
				if !strings.EqualFold(cols[0], selinuxlable) {
					return fmt.Errorf("selinuxlable  expected: %v, actual: %v", cols[0], selinuxlable)
				}
			}
		}
	}
	return nil
}
