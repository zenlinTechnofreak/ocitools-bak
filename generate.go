package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
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
	cli.BoolFlag{Name: "terminal", Usage: "creates an interactive terminal for the container"},
	cli.StringSliceFlag{Name: "uidmappings", Usage: "add UIDMappings e.g 0:0:10"},
	cli.StringSliceFlag{Name: "gidmappings", Usage: "add GIDMappings e.g[0:0:10]"},
	cli.StringSliceFlag{Name: "rlimit", Usage: "specifies rlimit options to apply to the container's process"},
	cli.StringSliceFlag{Name: "sysctl", Usage: "Sysctl are a set of key value pairs that are set for the container on start"},
	cli.StringFlag{Name: "cgroupspath", Usage: "specifies the path to cgroups that are created and/or joined by the container"},
	cli.StringFlag{Name: "apparmor", Usage: "specifies the the apparmor profile for the container"},
	cli.StringSliceFlag{Name: "device-add", Usage: "add device nodes that are created and enabled for the container"},
	cli.StringFlag{Name: "seccomp-default", Usage: "specifies the the defaultaction of Seccomp syscall restrictions"},
	cli.StringSliceFlag{Name: "seccomp-arch", Usage: "specifies Additional architectures permitted to be used for system calls"},
	cli.StringSliceFlag{Name: "seccomp-syscalls", Usage: "specifies Additional architectures permitted to be used for system calls, e.g[getcwd:SCMP_ACT_ERRNO:1/1/2/SCMP_CMP_GE,3/3/3/SCMP_CMP_GT]"},
	cli.BoolFlag{Name: "disableoomiller", Usage: "disables the OOM killer for out of memory conditions"},
	cli.StringFlag{Name: "memory", Usage: "define Memory restriction configuration"},
	cli.StringFlag{Name: "cpu", Usage: "define  CPU resource restriction configuration"},
	cli.IntFlag{Name: "pids", Usage: "define  Maximum number of PIDs"},
	cli.IntFlag{Name: "blockio-weight", Usage: "Specifies per cgroup weight, range is from 10 to 1000"},
	cli.IntFlag{Name: "blockio-leafweight", Usage: "Specifies tasks' weight in the given cgroup while competing with the cgroup's child cgroups, range is from 10 to 1000, cfq scheduler only"},
	cli.StringSliceFlag{Name: "weightdevice", Usage: "Weight per cgroup per device"},
	cli.StringSliceFlag{Name: "throttlereadbpsdevice", Usage: "IO read rate limit per cgroup per device,bytes per second"},
	cli.StringSliceFlag{Name: "throttlewritebpsdevice", Usage: "IO write rate limit per cgroup per device,bytes per second"},
	cli.StringSliceFlag{Name: "throttlereadiopsdevice", Usage: "IO read rate limit per cgroup per device,IO per second"},
	cli.StringSliceFlag{Name: "throttlewriteiopsdevice", Usage: "IO write rate limit per cgroup per device,IO per second"},
	cli.StringSliceFlag{Name: "hugepagelimit", Usage: "Hugetlb limit (in bytes)"},
	cli.StringFlag{Name: "networkid", Usage: " Set class identifier for container's network packets"},
	cli.StringSliceFlag{Name: "networkpriority ", Usage: "Set priority of network traffic for container"},
	cli.StringSliceFlag{Name: "mounts", Usage: "Mounts is a mapping of names to mount configurations"},
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
	spec.Process.Terminal = context.Bool("terminal")
	rspec.Linux.CgroupsPath = context.String("cgroupspath")
	rspec.Linux.ApparmorProfile = context.String("apparmor")
	rspec.Linux.Resources.DisableOOMKiller = context.Bool("disableoomiller")
	rspec.Linux.Resources.Pids.Limit = int64(context.Int("pids"))
	rspec.Linux.Resources.Network.ClassID = context.String("networkid")

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
	if err := setUIDMappings(spec, rspec, context); err != nil {
		return err
	}
	if err := setGIDMappings(spec, rspec, context); err != nil {
		return err
	}
	if err := setRlimits(spec, rspec, context); err != nil {
		return err
	}
	if err := setSysctl(spec, rspec, context); err != nil {
		return err
	}
	if err := addDevice(spec, rspec, context); err != nil {
		return err
	}
	if err := setSeccompDefaultAction(spec, rspec, context); err != nil {
		return err
	}
	if err := addSeccompArchitectures(spec, rspec, context); err != nil {
		return err
	}
	if err := addSeccompSyscalls(spec, rspec, context); err != nil {
		return err
	}
	if err := addHugepageLimit(spec, rspec, context); err != nil {
		return err
	}
	if err := addNetworkPriority(spec, rspec, context); err != nil {
		return err
	}
	if err := addMounts(spec, rspec, context); err != nil {
		return err
	}
	if err := addBlockIO(spec, rspec, context); err != nil {
		return err
	}
	if err := setResourceMemory(spec, rspec, context); err != nil {
		return err
	}
	if err := setResourceCPU(spec, rspec, context); err != nil {
		return err
	}
	return nil
}

func addBlockIO(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec, context *cli.Context) error {
	if context.Int("blockio-weight") != 0 {
		if context.Int("blockio-weight") > 1000 || context.Int("blockio-weight") < 10 {
			return fmt.Errorf("blockio-weight range is from 10 to 1000")
		}
		rspec.Linux.Resources.BlockIO.Weight = uint16(context.Int("blockio-weight"))
	}

	if context.Int("blockio-leafweight") != 0 {
		if context.Int("blockio-leafweight") > 1000 || context.Int("blockio-leafweight") < 10 {
			return fmt.Errorf("blockio-leafweight range is from 10 to 1000")
		}
		rspec.Linux.Resources.BlockIO.LeafWeight = uint16(context.Int("blockio-leafweight"))
	}
	for _, trbds := range context.StringSlice("throttlereadbpsdevice") {
		trbd := strings.Split(trbds, ":")
		if len(trbd) == 2 {
			fmt.Println("trbd=" + trbd[0])
			blockIODevicestr := trbd[0]
			rate, err := strconv.Atoi(trbd[1])
			b := strings.Split(blockIODevicestr, ",")
			if err != nil {
				return err
			}
			if len(b) == 2 {
				// major, err := strconv.Atoi(b[0])
				// minor, err := strconv.Atoi(b[1])
				// if err != nil {
				// 	return err
				// }
				// td := specs.ThrottleDevice{Rate: uint64(rate)}
				// td.blockIODevice.Major = int64(major)
				// td.blockIODevice.Minor = int64(minor)
				td := specs.ThrottleDevice{Rate: uint64(rate)}
				rspec.Linux.Resources.BlockIO.ThrottleReadBpsDevice = append(rspec.Linux.Resources.BlockIO.ThrottleReadBpsDevice, &td)
			} else {
				return fmt.Errorf("throttlereadbpsdevice error: %s", blockIODevicestr)
			}
		} else {
			return fmt.Errorf("throttlereadbpsdevice error: %s", trbds)
		}
	}
	return nil
}

func addMounts(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec, context *cli.Context) error {
	for _, mnts := range context.StringSlice("mounts") {
		mnt := strings.Split(mnts, ":")
		if len(mnt) == 4 {
			mp := mnt[0]
			tp := mnt[1]
			src := mnt[2]
			ops := strings.Split(mnt[3], ",")
			mounts := specs.Mount{tp, src, ops}
			rspec.Mounts[mp] = mounts
		} else {
			return fmt.Errorf("mounts error: %s", mnts)
		}
	}
	return nil
}

func addNetworkPriority(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec, context *cli.Context) error {
	for _, nps := range context.StringSlice("networkpriority") {
		np := strings.Split(nps, ":")
		if len(np) == 2 {
			priority, err := strconv.Atoi(np[1])
			if err != nil {
				return err
			}
			p := specs.InterfacePriority{np[0], int64(priority)}
			rspec.Linux.Resources.Network.Priorities = append(rspec.Linux.Resources.Network.Priorities, p)
		} else {
			return fmt.Errorf("networkpriority error: %s", nps)
		}
	}
	return nil
}

func addHugepageLimit(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec, context *cli.Context) error {
	for _, hpls := range context.StringSlice("hugepagelimit") {
		hpl := strings.Split(hpls, ":")
		if len(hpl) == 2 {
			limits, err := strconv.Atoi(hpl[1])
			if err != nil {
				return err
			}
			hp := specs.HugepageLimit{hpl[0], uint64(limits)}
			rspec.Linux.Resources.HugepageLimits = append(rspec.Linux.Resources.HugepageLimits, hp)
		} else {
			return fmt.Errorf("hugepagelimit error: %s", hpls)
		}
	}
	return nil
}

func setResourceCPU(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec, context *cli.Context) error {
	cpustr := context.String("cpu")
	if strings.EqualFold(cpustr, "") {
		return nil
	}
	cpu := strings.Split(cpustr, ":")
	if len(cpu) == 7 {
		shares, err := strconv.Atoi(cpu[0])
		quota, err := strconv.Atoi(cpu[1])
		period, err := strconv.Atoi(cpu[2])
		realtimeruntime, err := strconv.Atoi(cpu[3])
		realtimeperiod, err := strconv.Atoi(cpu[4])
		if err != nil {
			return err
		}
		cpustruct := specs.CPU{int64(shares), int64(quota), int64(period), int64(realtimeruntime), int64(realtimeperiod), cpu[5], cpu[6]}
		rspec.Linux.Resources.CPU = cpustruct
	} else {
		return fmt.Errorf("cpu error: %s", cpustr)
	}
	return nil
}

func setResourceMemory(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec, context *cli.Context) error {
	mems := context.String("memory")
	if strings.EqualFold(mems, "") {
		return nil
	}
	mem := strings.Split(mems, ":")
	if len(mem) == 5 {
		limit, err := strconv.Atoi(mem[0])
		reservation, err := strconv.Atoi(mem[1])
		swap, err := strconv.Atoi(mem[2])
		kernel, err := strconv.Atoi(mem[3])
		swapniess, err := strconv.Atoi(mem[4])
		if err != nil {
			return err
		}
		memorystruct := specs.Memory{int64(limit), int64(reservation), int64(swap), int64(kernel), int64(swapniess)}
		rspec.Linux.Resources.Memory = memorystruct
	} else {
		return fmt.Errorf("memory error: %s", mems)
	}
	return nil
}

func addSeccompSyscalls(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec, context *cli.Context) error {
	for _, syscalls := range context.StringSlice("seccomp-syscalls") {
		syscall := strings.Split(syscalls, ":")
		if len(syscall) == 3 {
			name := syscall[0]
			switch syscall[1] {
			case "":
			case "SCMP_ACT_KILL":
			case "SCMP_ACT_TRAP":
			case "SCMP_ACT_ERRNO":
			case "SCMP_ACT_TRACE":
			case "SCMP_ACT_ALLOW":
			default:
				return fmt.Errorf("seccomp-sysctl action must be empty or one of SCMP_ACT_KILL|SCMP_ACT_TRAP|SCMP_ACT_ERRNO|SCMP_ACT_TRACE|SCMP_ACT_ALLOW")
			}
			action := specs.Action(syscall[1])
			var Args []*specs.Arg
			argsslice := strings.Split(syscall[2], ",")
			for _, argsstru := range argsslice {
				args := strings.Split(argsstru, "/")
				if len(args) == 4 {
					index, err := strconv.Atoi(args[0])
					value, err := strconv.Atoi(args[1])
					value2, err := strconv.Atoi(args[2])
					if err != nil {
						return err
					}
					switch args[3] {
					case "":
					case "SCMP_CMP_NE":
					case "SCMP_CMP_LT":
					case "SCMP_CMP_LE":
					case "SCMP_CMP_EQ":
					case "SCMP_CMP_GE":
					case "SCMP_CMP_GT":
					case "SCMP_CMP_MASKED_EQ":
					default:
						return fmt.Errorf("seccomp-sysctl args must be empty or one of SCMP_CMP_NE|SCMP_CMP_LT|SCMP_CMP_LE|SCMP_CMP_EQ|SCMP_CMP_GE|SCMP_CMP_GT|SCMP_CMP_MASKED_EQ")
					}
					op := specs.Operator(args[3])
					Arg := specs.Arg{uint(index), uint64(value), uint64(value2), op}
					Args = append(Args, &Arg)
				} else {
					return fmt.Errorf("seccomp-sysctl args error: %s", argsstru)
				}
			}
			syscallstruct := specs.Syscall{name, action, Args}
			rspec.Linux.Seccomp.Syscalls = append(rspec.Linux.Seccomp.Syscalls, &syscallstruct)
		} else {
			return fmt.Errorf("seccomp sysctl must consits 3 parameters")
		}
	}
	return nil
}

func addSeccompArchitectures(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec, context *cli.Context) error {
	for _, archs := range context.StringSlice("seccomp-arch") {
		switch archs {
		case "":
		case "SCMP_ARCH_X86":
		case "SCMP_ARCH_X86_64":
		case "SCMP_ARCH_X32":
		case "SCMP_ARCH_ARM":
		case "SCMP_ARCH_AARCH64":
		case "SCMP_ARCH_MIPS":
		case "SCMP_ARCH_MIPS64":
		case "SCMP_ARCH_MIPS64N32":
		case "SCMP_ARCH_MIPSEL":
		case "SCMP_ARCH_MIPSEL64":
		case "SCMP_ARCH_MIPSEL64N32":
		default:
			return fmt.Errorf("seccomp-arch must be empty or one of SCMP_ARCH_X86|SCMP_ARCH_X86_64|SCMP_ARCH_X32|SCMP_ARCH_ARM|SCMP_ARCH_AARCH64SCMP_ARCH_MIPS|SCMP_ARCH_MIPS64|SCMP_ARCH_MIPS64N32|SCMP_ARCH_MIPSEL|SCMP_ARCH_MIPSEL64|SCMP_ARCH_MIPSEL64N32")
		}
		rspec.Linux.Seccomp.Architectures = append(rspec.Linux.Seccomp.Architectures, specs.Arch(archs))
	}
	return nil
}

func setSeccompDefaultAction(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec, context *cli.Context) error {
	sd := context.String("seccomp-default")
	switch sd {
	case "":
	case "SCMP_ACT_KILL":
	case "SCMP_ACT_TRAP":
	case "SCMP_ACT_ERRNO":
	case "SCMP_ACT_TRACE":
	case "SCMP_ACT_ALLOW":
	default:
		return fmt.Errorf("seccomp-default must be empty or one of SCMP_ACT_KILL|SCMP_ACT_TRAP|SCMP_ACT_ERRNO|SCMP_ACT_TRACE|SCMP_ACT_ALLOW")
	}
	rspec.Linux.Seccomp.DefaultAction = specs.Action(sd)
	return nil
}

func addDevice(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec, context *cli.Context) error {
	for _, devs := range context.StringSlice("device-add") {
		dev := strings.Split(devs, ":")
		if len(dev) == 8 {
			path := dev[0]
			rtemp := []rune(dev[1])
			typ := rtemp[0]
			major, err := strconv.Atoi(dev[2])
			minor, err := strconv.Atoi(dev[3])
			permi := dev[4]
			filemodle, err := strconv.Atoi(dev[5])
			fm := os.FileMode(filemodle)
			uid, err := strconv.Atoi(dev[6])
			gid, err := strconv.Atoi(dev[7])
			if err != nil {
				return err
			}
			device := specs.Device{path, typ, int64(major), int64(minor), permi, fm, uint32(uid), uint32(gid)}
			rspec.Linux.Devices = append(rspec.Linux.Devices, device)
		} else {
			return fmt.Errorf("Device-add error: %s", devs)
		}
	}
	return nil
}

func setSysctl(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec, context *cli.Context) error {
	m := make(map[string]string)
	for _, scs := range context.StringSlice("sysctl") {
		sc := strings.Split(scs, ":")
		if len(sc) == 2 {
			m[sc[0]] = sc[1]
		} else {
			return fmt.Errorf("sysctl error: %s", scs)
		}
	}
	rspec.Linux.Sysctl = m
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

func setUIDMappings(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec, context *cli.Context) error {
	for _, idms := range context.StringSlice("uidmappings") {
		idm := strings.Split(idms, ":")
		if len(idm) == 3 {
			hid, err := strconv.Atoi(idm[0])
			cid, err := strconv.Atoi(idm[1])
			size, err := strconv.Atoi(idm[2])
			if err != nil {
				return err
			}
			uidmapping := specs.IDMapping{uint32(hid), uint32(cid), uint32(size)}
			rspec.Linux.UIDMappings = append(rspec.Linux.UIDMappings, uidmapping)
		} else {
			return fmt.Errorf("uidmappings error: %s", idms)
		}
	}
	return nil
}

func setGIDMappings(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec, context *cli.Context) error {
	for _, idms := range context.StringSlice("gidmappings") {
		idm := strings.Split(idms, ":")
		if len(idm) == 3 {
			hid, err := strconv.Atoi(idm[0])
			cid, err := strconv.Atoi(idm[1])
			size, err := strconv.Atoi(idm[2])
			if err != nil {
				return err
			}
			gidmapping := specs.IDMapping{uint32(hid), uint32(cid), uint32(size)}
			rspec.Linux.GIDMappings = append(rspec.Linux.GIDMappings, gidmapping)
		} else {
			return fmt.Errorf("gidmappings error: %s", idms)
		}
	}
	return nil
}

func setRlimits(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec, context *cli.Context) error {
	for _, rls := range context.StringSlice("rlimit") {
		rl := strings.Split(rls, ":")
		if len(rl) == 3 {
			hard, _ := strconv.Atoi(rl[1])
			soft, _ := strconv.Atoi(rl[2])
			rlimit := specs.Rlimit{rl[0], uint64(hard), uint64(soft)}
			rspec.Linux.Rlimits = append(rspec.Linux.Rlimits, rlimit)
		} else {
			return fmt.Errorf("rlimits error: %s", rls)
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
