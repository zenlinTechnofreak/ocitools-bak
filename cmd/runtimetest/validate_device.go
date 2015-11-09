package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/opencontainers/specs"
)

func validateDevices(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec) error {
	devices := rspec.Linux.Devices
	fmt.Println("enter device")
	if devices != nil {
		for _, device := range devices {
			fmt.Println(device)
			path := device.Path
			devinfo, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("device %s not exsist", path)
			}
			devmode := devinfo.Mode()
			permissions := os.FileMode.Perm(devmode)
			var devtype rune
			switch {
			case devmode&os.ModeDevice == 0:
				return fmt.Errorf("device %s is not a device", path)
			case devmode&os.ModeCharDevice != 0:
				permissions |= syscall.S_IFCHR
				devtype = 'c'
				// case devmode&os.ModeNamedPipe != 0:
				// 	permissions |= syscall.S_IFIFO
				// 	devtype = 'p'
			default:
				permissions |= syscall.S_IFBLK
				devtype = 'b'
			}
			stat, ok := devinfo.Sys().(*syscall.Stat_t)
			if !ok {
				return fmt.Errorf("cannot determine the device number for device %s", path)
			}
			if devtype != device.Type {
				return fmt.Errorf("device type expected: %v, actual: %v", device.Type, devtype)
			}
			if !strings.EqualFold(permissions.String(), device.FileMode.String()) {
				return fmt.Errorf("device filemode expected: %v, actual: %v", device.Permissions, permissions.String())
			}
			if stat.Uid != device.UID {
				return fmt.Errorf("device uid expected: %v, actual: %v", device.UID, stat.Uid)
			}
			if stat.Gid != device.GID {
				return fmt.Errorf("device gid expected: %v, actual: %v", device.GID, stat.Gid)
			}
		}
	}
	return nil
}
