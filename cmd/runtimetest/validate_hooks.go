package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/opencontainers/specs"
)

func validateHooks(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec) error {
	if rspec.Hooks.Prestart != nil {
		for _, prestart := range rspec.Hooks.Prestart {
			if strings.EqualFold(prestart.Path, "/bin/mkdir") && strings.EqualFold(prestart.Args[0], "./rootfs/prestarthook") {
				if _, err := os.Stat("/prestarthook"); os.IsNotExist(err) {
					return fmt.Errorf("Prestart Hook validate failed")
				}
			}
		}
	}
	return nil
}
