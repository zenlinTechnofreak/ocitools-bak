package main

import (
	"fmt"
	"os"

	"github.com/opencontainers/specs"
)

func validateHostname(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec) error {
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	if hostname != spec.Hostname {
		return fmt.Errorf("Hostname expected: %v, actual: %v", spec.Hostname, hostname)
	}
	return nil
}
