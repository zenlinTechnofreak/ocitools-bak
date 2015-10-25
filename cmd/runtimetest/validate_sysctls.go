package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/opencontainers/specs"
)

func validateSysctls(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec) error {
	for k, v := range rspec.Linux.Sysctl {
		keyPath := filepath.Join("/proc/sys", strings.Replace(k, ".", "/", -1))
		vBytes, err := ioutil.ReadFile(keyPath)
		if err != nil {
			return err
		}
		value := strings.TrimSpace(string(bytes.Trim(vBytes, "\x00")))
		if value != v {
			return fmt.Errorf("Sysctl %v value expected: %v, actual: %v", k, v, value)
		}
	}
	return nil
}
