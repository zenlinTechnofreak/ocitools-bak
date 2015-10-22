package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/opencontainers/specs"
	"github.com/syndtr/gocapability/capability"
)

var generateFlags = []cli.Flag{
	cli.StringFlag{Name: "rootfs", Usage: "path to the rootfs"},
	cli.BoolFlag{Name: "read-only", Usage: "make the container's rootfs read-only"},
	cli.BoolFlag{Name: "privileged", Usage: "enabled privileged container settings"},
	cli.StringFlag{Name: "hostname", Value: "acme", Usage: "hostname value for the container"},
	cli.IntFlag{Name: "uid", Usage: "uid for the process"},
	cli.IntFlag{Name: "gid", Usage: "gid for the process"},
	cli.StringSliceFlag{Name: "groups", Usage: "supplementary groups for the process"},
	cli.StringSliceFlag{Name: "cap-add", Usage: "add capabilities"},
	cli.StringSliceFlag{Name: "cap-drop", Usage: "drop capabilities"},
	cli.StringFlag{Name: "network", Usage: "network namespace"},
	cli.StringFlag{Name: "mount", Usage: "mount namespace"},
	cli.StringFlag{Name: "pid", Usage: "pid namespace"},
	cli.StringFlag{Name: "ipc", Usage: "ipc namespace"},
	cli.StringFlag{Name: "uts", Usage: "uts namespace"},
	cli.StringFlag{Name: "selinux-label", Usage: "process selinux label"},
	cli.StringSliceFlag{Name: "tmpfs", Usage: "mount tmpfs"},
	cli.StringFlag{Name: "args", Usage: "command to run in the container"},
	cli.StringSliceFlag{Name: "env", Usage: "add environment variable"},
	cli.StringFlag{Name: "mount-cgroups", Value: "ro", Usage: "mount cgroups (rw,ro,no)"},
	cli.StringSliceFlag{Name: "bind", Usage: "bind mount directories src:dest:(rw,ro)"},
	cli.StringSliceFlag{Name: "prestart", Usage: "path to prestart hooks"},
	cli.StringSliceFlag{Name: "poststop", Usage: "path to poststop hooks"},
	cli.StringSliceFlag{Name: "poststart", Usage: "path to poststart hooks"},
	cli.StringFlag{Name: "root-propagation", Usage: "mount propagation for root"},
	cli.StringFlag{Name: "version", Value: "0.2.0", Usage: "version of the specification"},
	cli.StringFlag{Name: "os", Value: runtime.GOOS, Usage: "operating system the container is created for"},
	cli.StringFlag{Name: "arch", Value: runtime.GOARCH, Usage: "architecture the container is created for"},
	cli.StringFlag{Name: "cwd", Usage: "current working directory for the process"},
	cli.StringSliceFlag{Name: "mountpoint-add", Usage: "add mountpoints"},
}

var (
	defaultCaps = []string{
		"CAP_CHOWN",
		"CAP_DAC_OVERRIDE",
		"CAP_FSETID",
		"CAP_FOWNER",
		"CAP_MKNOD",
		"CAP_NET_RAW",
		"CAP_SETGID",
		"CAP_SETUID",
		"CAP_SETFCAP",
		"CAP_SETPCAP",
		"CAP_NET_BIND_SERVICE",
		"CAP_SYS_CHROOT",
		"CAP_KILL",
		"CAP_AUDIT_WRITE",
	}
)

var generateCommand = cli.Command{
	Name:  "generate",
	Usage: "generate a OCI spec file",
	Flags: generateFlags,
	Action: func(context *cli.Context) {
		spec, rspec := getDefaultTemplate()
		err := modify(&spec, &rspec, context)
		if err != nil {
			logrus.Fatal(err)
		}
		cName := "config.json"
		rName := "runtime.json"
		data, err := json.MarshalIndent(&spec, "", "\t")
		if err != nil {
			logrus.Fatal(err)
		}
		if err := ioutil.WriteFile(cName, data, 0666); err != nil {
			logrus.Fatal(err)
		}
		rdata, err := json.MarshalIndent(&rspec, "", "\t")
		if err != nil {
			logrus.Fatal(err)
		}
		if err := ioutil.WriteFile(rName, rdata, 0666); err != nil {
			logrus.Fatal(err)
		}
	},
}

func modify(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec, context *cli.Context) error {
	spec.Root.Path = context.String("rootfs")
	spec.Root.Readonly = context.Bool("read-only")
	spec.Hostname = context.String("hostname")
	spec.Process.User.UID = uint32(context.Int("uid"))
	spec.Process.User.GID = uint32(context.Int("gid"))
	rspec.Linux.SelinuxProcessLabel = context.String("selinux-label")
	spec.Version = context.String("version")
	spec.Platform.OS = context.String("os")
	spec.Platform.Arch = context.String("arch")
	spec.Process.Cwd = context.String("cwd")

	args := context.String("args")
	if args != "" {
		spec.Process.Args = []string{args}
	}

	for _, e := range context.StringSlice("env") {
		spec.Process.Env = append(spec.Process.Env, e)
	}

	groups := context.StringSlice("groups")
	if groups != nil {
		for _, g := range groups {
			groupId, err := strconv.Atoi(g)
			if err != nil {
				return err
			}
			spec.Process.User.AdditionalGids = append(spec.Process.User.AdditionalGids, uint32(groupId))
		}
	}

	if err := setupCapabilities(spec, rspec, context); err != nil {
		return err
	}
	setupNamespaces(spec, rspec, context)
	if err := addTmpfsMounts(spec, rspec, context); err != nil {
		return err
	}
	if err := mountCgroups(spec, rspec, context); err != nil {
		return err
	}
	if err := addBindMounts(spec, rspec, context); err != nil {
		return err
	}
	if err := addHooks(spec, rspec, context); err != nil {
		return err
	}
	if err := addRootPropagation(spec, rspec, context); err != nil {
		return err
	}
	if err := addMountPoint(spec, rspec, context); err != nil {
		return err
	}

	return nil
}

func addMountPoint(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec, context *cli.Context) error {
	for _, mps := range context.StringSlice("mountpoint-add") {
		mp := strings.Split(mps, ":")
		if len(mp) == 2 {
			newmp := specs.MountPoint{mp[0], mp[1]}
			spec.Mounts = append(spec.Mounts, newmp)
		} else {
			return fmt.Errorf("mountpoint-add error: %s", mps)
		}
	}
	return nil
}

func addRootPropagation(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec, context *cli.Context) error {
	rp := context.String("root-propagation")
	switch rp {
	case "":
	case "private":
	case "rprivate":
	case "slave":
	case "rslave":
	case "shared":
	case "rshared":
	default:
		return fmt.Errorf("rootfs-propagation must be empty or one of private|rprivate|slave|rslave|shared|rshared")
	}
	rspec.Linux.RootfsPropagation = rp
	return nil
}

func addHooks(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec, context *cli.Context) error {
	for _, pre := range context.StringSlice("prestart") {
		parts := strings.Split(pre, ":")
		args := []string{}
		path := parts[0]
		if len(parts) > 1 {
			args = parts[1:]
		}
		rspec.Hooks.Prestart = append(rspec.Hooks.Prestart, specs.Hook{Path: path, Args: args})
	}
	for _, post := range context.StringSlice("poststop") {
		parts := strings.Split(post, ":")
		args := []string{}
		path := parts[0]
		if len(parts) > 1 {
			args = parts[1:]
		}
		rspec.Hooks.Poststop = append(rspec.Hooks.Poststop, specs.Hook{Path: path, Args: args})
	}
	for _, post := range context.StringSlice("poststart") {
		parts := strings.Split(post, ":")
		args := []string{}
		path := parts[0]
		if len(parts) > 1 {
			args = parts[1:]
		}
		rspec.Hooks.Poststart = append(rspec.Hooks.Poststart, specs.Hook{Path: path, Args: args})
	}
	return nil
}
func addTmpfsMounts(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec, context *cli.Context) error {
	for _, dest := range context.StringSlice("tmpfs") {
		name := filepath.Base(dest)
		mntName := fmt.Sprintf("%stmpfs", name)
		mnt := specs.MountPoint{Name: mntName, Path: dest}
		spec.Mounts = append(spec.Mounts, mnt)
		rmnt := specs.Mount{
			Type:    "tmpfs",
			Source:  "tmpfs",
			Options: []string{"nosuid", "nodev", "mode=755"},
		}
		rspec.Mounts[mntName] = rmnt
	}
	return nil
}

func mountCgroups(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec, context *cli.Context) error {
	mountCgroupOption := context.String("mount-cgroups")
	switch mountCgroupOption {
	case "ro":
	case "rw":
	case "no":
		return nil
	default:
		return fmt.Errorf("--mount-cgroups should be one of (ro,rw,no)")
	}

	spec.Mounts = append(spec.Mounts, specs.MountPoint{Name: "cgroup", Path: "/sys/fs/cgroup"})
	rspec.Mounts["cgroup"] = specs.Mount{
		Type:    "cgroup",
		Source:  "cgroup",
		Options: []string{"nosuid", "noexec", "nodev", "relatime", mountCgroupOption},
	}

	return nil
}

func addBindMounts(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec, context *cli.Context) error {
	for _, b := range context.StringSlice("bind") {
		var source, dest string
		options := "ro"
		bparts := strings.SplitN(b, ":", 3)
		switch len(bparts) {
		case 2:
			source, dest = bparts[0], bparts[1]
		case 3:
			source, dest, options = bparts[0], bparts[1], bparts[2]
		default:
			return fmt.Errorf("--bind should have format src:dest:[options]")
		}
		name := filepath.Base(source)
		mntName := fmt.Sprintf("%sbind", name)
		spec.Mounts = append(spec.Mounts, specs.MountPoint{Name: mntName, Path: dest})
		defaultOptions := []string{"bind"}
		rspec.Mounts[mntName] = specs.Mount{
			Type:    "bind",
			Source:  source,
			Options: append(defaultOptions, options),
		}
	}
	return nil
}

func setupCapabilities(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec, context *cli.Context) error {
	var finalCapList []string

	// Add all capabilities in privileged mode.
	privileged := context.Bool("privileged")
	if privileged {
		for _, cap := range capability.List() {
			finalCapList = append(finalCapList, fmt.Sprintf("CAP_%s", strings.ToUpper(cap.String())))
		}
		spec.Linux.Capabilities = finalCapList
		return nil
	}

	capMappings := make(map[string]bool)
	for _, cap := range capability.List() {
		key := strings.ToUpper(cap.String())
		capMappings[key] = true
	}

	addedCapsMap := make(map[string]bool)
	for _, cap := range defaultCaps {
		addedCapsMap[cap] = true
	}

	addCapList := make([]string, len(defaultCaps))
	copy(addCapList, defaultCaps)
	addCaps := context.StringSlice("cap-add")
	for _, c := range addCaps {
		if !capMappings[c] {
			return fmt.Errorf("Invalid value passed for adding capability")
		}
		cp := fmt.Sprintf("CAP_%s", c)
		if !addedCapsMap[cp] {
			addCapList = append(addCapList, cp)
			addedCapsMap[cp] = true
		}
	}
	dropCaps := context.StringSlice("cap-drop")
	dropCapsMap := make(map[string]bool)
	for _, c := range dropCaps {
		if !capMappings[c] {
			return fmt.Errorf("Invalid value passed for dropping capability")
		}
		cp := fmt.Sprintf("CAP_%s", c)
		dropCapsMap[cp] = true
	}

	for _, c := range addCapList {
		if !dropCapsMap[c] {
			finalCapList = append(finalCapList, c)
		}
	}
	spec.Linux.Capabilities = finalCapList
	return nil
}

func mapStrToNamespace(ns string, path string) specs.Namespace {
	switch ns {
	case "network":
		return specs.Namespace{Type: specs.NetworkNamespace, Path: path}
	case "pid":
		return specs.Namespace{Type: specs.PIDNamespace, Path: path}
	case "mount":
		return specs.Namespace{Type: specs.MountNamespace, Path: path}
	case "ipc":
		return specs.Namespace{Type: specs.IPCNamespace, Path: path}
	case "uts":
		return specs.Namespace{Type: specs.UTSNamespace, Path: path}
	case "user":
		return specs.Namespace{Type: specs.UserNamespace, Path: path}
	default:
		logrus.Fatalf("Should not reach here!")
	}
	return specs.Namespace{}
}

func setupNamespaces(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec, context *cli.Context) {
	namespaces := []string{"network", "pid", "mount", "ipc", "uts"}
	var linuxNs []specs.Namespace
	for _, nsName := range namespaces {
		nsPath := context.String(nsName)
		if nsPath == "host" {
			continue
		}
		ns := mapStrToNamespace(nsName, nsPath)
		linuxNs = append(linuxNs, ns)
	}
	rspec.Linux.Namespaces = linuxNs
}

func getDefaultTemplate() (specs.LinuxSpec, specs.LinuxRuntimeSpec) {
	spec := specs.LinuxSpec{
		Spec: specs.Spec{
			Version: specs.Version,
			Platform: specs.Platform{
				OS:   runtime.GOOS,
				Arch: runtime.GOARCH,
			},
			Root: specs.Root{
				Path:     "",
				Readonly: false,
			},
			Process: specs.Process{
				Terminal: true,
				User:     specs.User{},
				Args: []string{
					"sh",
				},
				Env: []string{
					"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
					"TERM=xterm",
				},
			},
			Hostname: "shell",
			Mounts: []specs.MountPoint{
				{
					Name: "proc",
					Path: "/proc",
				},
				{
					Name: "dev",
					Path: "/dev",
				},
				{
					Name: "devpts",
					Path: "/dev/pts",
				},
				{
					Name: "shm",
					Path: "/dev/shm",
				},
				{
					Name: "mqueue",
					Path: "/dev/mqueue",
				},
				{
					Name: "sysfs",
					Path: "/sys",
				},
			},
		},
		Linux: specs.Linux{
			Capabilities: []string{
				"CAP_CHOWN",
				"CAP_DAC_OVERRIDE",
				"CAP_FSETID",
				"CAP_FOWNER",
				"CAP_MKNOD",
				"CAP_NET_RAW",
				"CAP_SETGID",
				"CAP_SETUID",
				"CAP_SETFCAP",
				"CAP_SETPCAP",
				"CAP_NET_BIND_SERVICE",
				"CAP_SYS_CHROOT",
				"CAP_KILL",
				"CAP_AUDIT_WRITE",
			},
		},
	}
	rspec := specs.LinuxRuntimeSpec{
		RuntimeSpec: specs.RuntimeSpec{
			Mounts: map[string]specs.Mount{
				"proc": {
					Type:    "proc",
					Source:  "proc",
					Options: nil,
				},
				"dev": {
					Type:    "tmpfs",
					Source:  "tmpfs",
					Options: []string{"nosuid", "strictatime", "mode=755", "size=65536k"},
				},
				"devpts": {
					Type:    "devpts",
					Source:  "devpts",
					Options: []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"},
				},
				"shm": {
					Type:    "tmpfs",
					Source:  "shm",
					Options: []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"},
				},
				"mqueue": {
					Type:    "mqueue",
					Source:  "mqueue",
					Options: []string{"nosuid", "noexec", "nodev"},
				},
				"sysfs": {
					Type:    "sysfs",
					Source:  "sysfs",
					Options: []string{"nosuid", "noexec", "nodev"},
				},
			},
		},
		Linux: specs.LinuxRuntime{
			Namespaces: []specs.Namespace{
				{
					Type: "pid",
				},
				{
					Type: "network",
				},
				{
					Type: "ipc",
				},
				{
					Type: "uts",
				},
				{
					Type: "mount",
				},
			},
			Rlimits: []specs.Rlimit{
				{
					Type: "RLIMIT_NOFILE",
					Hard: uint64(1024),
					Soft: uint64(1024),
				},
			},
			Devices: []specs.Device{
				{
					Type:        'c',
					Path:        "/dev/null",
					Major:       1,
					Minor:       3,
					Permissions: "rwm",
					FileMode:    0666,
					UID:         0,
					GID:         0,
				},
				{
					Type:        'c',
					Path:        "/dev/random",
					Major:       1,
					Minor:       8,
					Permissions: "rwm",
					FileMode:    0666,
					UID:         0,
					GID:         0,
				},
				{
					Type:        'c',
					Path:        "/dev/full",
					Major:       1,
					Minor:       7,
					Permissions: "rwm",
					FileMode:    0666,
					UID:         0,
					GID:         0,
				},
				{
					Type:        'c',
					Path:        "/dev/tty",
					Major:       5,
					Minor:       0,
					Permissions: "rwm",
					FileMode:    0666,
					UID:         0,
					GID:         0,
				},
				{
					Type:        'c',
					Path:        "/dev/zero",
					Major:       1,
					Minor:       5,
					Permissions: "rwm",
					FileMode:    0666,
					UID:         0,
					GID:         0,
				},
				{
					Type:        'c',
					Path:        "/dev/urandom",
					Major:       1,
					Minor:       9,
					Permissions: "rwm",
					FileMode:    0666,
					UID:         0,
					GID:         0,
				},
			},
			Resources: &specs.Resources{
				Memory: specs.Memory{
					Swappiness: -1,
				},
			},
		},
	}
	return spec, rspec
}
