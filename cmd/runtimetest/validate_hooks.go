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
			if strings.EqualFold(prestart.Path, "/bin/mkdir") && strings.EqualFold(prestart.Args[1], "./rootfs/prestarthook") {
				if _, err := os.Stat("/prestarthook"); os.IsNotExist(err) {
					return fmt.Errorf("Prestart Hook validate failed")
				}
			}
		}
	}
	if rspec.Hooks.Poststop != nil {
		for _, poststop := range rspec.Hooks.Poststop {
			if strings.EqualFold(poststop.Path, "/bin/mkdir") && strings.EqualFold(poststop.Args[1], "./rootfs/poststophook") {
				if _, err := os.Stat("/poststophook"); os.IsNotExist(err) {
					fmt.Println("[poststop_hookvalidate_output_start]")
					fmt.Println("folder poststophook is not exsist")
					fmt.Println("[poststop_hookvalidate_output_end]")
				}
			}
		}
	}
	return nil
}
