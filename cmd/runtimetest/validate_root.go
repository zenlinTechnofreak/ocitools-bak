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
	mntori, _ := ioutil.ReadFile("/proc/mounts")
	mnt := bytes.Split(mntori, []byte{'\n'})
	for _, row := range mnt {
		col := bytes.Split(row, []byte{' '})
		if len(col) == 6 && strings.EqualFold(string(col[1]), "/") && !strings.EqualFold(string(col[2]), "rootfs") {
			opstr := string(col[3])
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
