package main

import (
	"fmt"
	"github.com/opencontainers/specs"
	"runtime"
	"strings"
)

func validatePlatform(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec) error {
	os := spec.Platform.OS
	arch := spec.Platform.Arch
	hos := runtime.GOOS
	harch := runtime.GOARCH
	if !strings.EqualFold(os, hos) {
		return fmt.Errorf("OS expected: %v, actual: %v", os, hos)
	}
	if !strings.EqualFold(arch, harch) {
		return fmt.Errorf("Arch expected: %v, actual: %v", arch, harch)
	}
	return nil
}
