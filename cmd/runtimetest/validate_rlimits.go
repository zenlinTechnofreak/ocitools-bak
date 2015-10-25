package main

import (
	"fmt"
	"syscall"

	"github.com/opencontainers/specs"
)

func validateRlimits(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec) error {
	for _, r := range rspec.Linux.Rlimits {
		rl, err := strToRlimit(r.Type)
		if err != nil {
			return err
		}

		var rlimit syscall.Rlimit
		if err := syscall.Getrlimit(rl, &rlimit); err != nil {
			return err
		}

		if rlimit.Cur != r.Soft {
			return fmt.Errorf("%v rlimit soft expected: %v, actual: %v", r.Soft, rlimit.Cur)
		}
		if rlimit.Max != r.Hard {
			return fmt.Errorf("%v rlimit hard expected: %v, actual: %v", r.Hard, rlimit.Max)
		}
	}
	return nil
}
