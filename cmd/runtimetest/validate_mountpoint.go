package main

import (
	"bytes"
	"fmt"
	"github.com/opencontainers/specs"
	"io/ioutil"
	"strings"
)

func validateMount(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec) error {
	//read the /proc/mount file and covert to map[path]spec.mount
	mntori, _ := ioutil.ReadFile("/proc/mounts")
	mnt := bytes.Split(mntori, []byte{'\n'})
	containermnts := make(map[string]specs.Mount)
	for _, row := range mnt {
		col := bytes.Split(row, []byte{' '})
		if len(col) != 6 {
			break
		}
		ops := strings.Split(string(col[3]), ",")
		containermnts[string(col[1])] = specs.Mount{string(col[2]), "", ops}
	}
	//read  config.json and runtime.json and compare to con
	mntpts := spec.Mounts
	mnts := rspec.Mounts
	for _, mntpt := range mntpts {
		mnt := mnts[mntpt.Name]
		mntcotainer := containermnts[mntpt.Path]
		if !strings.EqualFold(mnt.Type, mntcotainer.Type) {
			return fmt.Errorf("mount.Type expected: %v, actual: %v", mnt.Type, mntcotainer.Type)
		}
	}
	return nil
}
