package main

import (
	"bytes"
	"fmt"
	"github.com/opencontainers/specs"
	"io/ioutil"
	"strings"
)

func validateMount(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec) error {
	//read the /proWc/mount file and covert to map[path]spec.mount
	fmt.Println("enter vanlidate mount ")
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
	//read  config.json and runtime.json and compare the mount
	mntpts := spec.Mounts
	mnts := rspec.Mounts
	fmt.Println(mntpts)
	for _, mntpt := range mntpts {
		fmt.Println(mntpt)
		mnt := mnts[mntpt.Name]
		mntcotainer, exsist := containermnts[mntpt.Path]
		if !exsist {
			return fmt.Errorf("mountpoint name:%v, path: %v doesn't exsist", mntpt.Name, mntpt.Path)
		}
		if strings.EqualFold(mnt.Type, "cgroup") && !strings.EqualFold(mntcotainer.Type, "tmpfs") {
			return fmt.Errorf("cgroup filesystem error")
		}
		if !strings.EqualFold(mnt.Type, "cgroup") && !strings.EqualFold(mnt.Type, mntcotainer.Type) {
			return fmt.Errorf("mount.Type expected: %v, actual: %v", mnt.Type, mntcotainer.Type)
		}
	}
	// TODO mount options validation

	return nil
}
