package main

import (
	"bytes"
	"fmt"
	"github.com/opencontainers/specs"
	"io/ioutil"
	"strings"
)

func validateRoot(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec) error {
	readonly := spec.Root.Readonly
	mntori, _ := ioutil.ReadFile("/proc/self/mountinfo")
	mnt := bytes.Split(mntori, []byte{'\n'})
	for _, row := range mnt {
		col := bytes.Split(row, []byte{' '})
		if len(col) == 10 && strings.EqualFold(string(col[4]), "/") {
			opstr := string(col[5])
			if strings.Contains(opstr, "rw,") && readonly == false {
				return nil
			} else if strings.Contains(opstr, "ro,") && readonly == true {
				return nil
			} else {
				return fmt.Errorf("rootfs readonly failed")
			}
		}
	}
	return nil
}
