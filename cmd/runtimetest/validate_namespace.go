package main

import (
	"fmt"
	"os"

	"github.com/opencontainers/specs"
)

func validateNamespace(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec) error {
	nslist := rspec.Linux.Namespaces
	fmt.Println("[namespace_output_start]")
	for _, ns := range nslist {
		var nstype string
		switch ns.Type {
		case "network":
			nstype = "net"
		case "pid":
			nstype = "pid"
		case "mount":
			nstype = "mnt"
		case "ipc":
			nstype = "ipc"
		case "uts":
			nstype = "uts"
		case "user":
			nstype = "user"
		default:
			return fmt.Errorf("namespace type is invalid")
		}

		link, err := os.Readlink("/proc/self/ns/" + nstype)
		if err != nil {
			return err
		}
		fmt.Println(link + "," + ns.Path)
	}
	fmt.Printf("[namespace_output_end]")
	return nil
}
