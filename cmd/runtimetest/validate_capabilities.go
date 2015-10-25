package main

import (
	"fmt"
	"strings"

	"github.com/opencontainers/specs"
	"github.com/syndtr/gocapability/capability"
)

func validateCapabilities(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec) error {
	capabilityMap := make(map[string]capability.Cap)
	expectedCaps := make(map[capability.Cap]bool)
	last := capability.CAP_LAST_CAP
	// workaround for RHEL6 which has no /proc/sys/kernel/cap_last_cap
	if last == capability.Cap(63) {
		last = capability.CAP_BLOCK_SUSPEND
	}
	for _, cap := range capability.List() {
		if cap > last {
			continue
		}
		capKey := fmt.Sprintf("CAP_%s", strings.ToUpper(cap.String()))
		capabilityMap[capKey] = cap
		expectedCaps[cap] = false
	}

	for _, ec := range spec.Linux.Capabilities {
		cap := capabilityMap[ec]
		expectedCaps[cap] = true
	}

	processCaps, err := capability.NewPid(1)
	if err != nil {
		return err
	}

	for _, cap := range capability.List() {
		expectedSet := expectedCaps[cap]
		actuallySet := processCaps.Get(capability.EFFECTIVE, cap)
		if expectedSet != actuallySet {
			if expectedSet {
				return fmt.Errorf("Expected Capability %v not set for process", cap.String())
			} else {
				return fmt.Errorf("Unexpected Capability %v set for process", cap.String())
			}
		}
	}

	return nil
}
