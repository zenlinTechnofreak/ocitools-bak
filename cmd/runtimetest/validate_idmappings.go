package main

import (
	"bytes"
	"fmt"
	"github.com/opencontainers/specs"
	"io/ioutil"
	"sort"
	"strconv"
	"strings"
)

func validateIDmappings(spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec) error {
	ums := rspec.Linux.UIDMappings
	fmt.Println("enter id")
	fmt.Println(ums)
	// gms := rspec.Linux.GIDMappings
	if ums != nil {
		out, _ := ioutil.ReadFile("/proc/1/uid_map")
		uidbytes := bytes.Split(out, []byte{'\n'})
		mappings := []string{}
		//convert the content of /proc/1/uid_map to stringslice
		// and each line in the file convert to string ,Formmat:HostID+ContainerID+Size
		for _, uidbyte := range uidbytes {
			uidstr := strings.Fields(string(uidbyte))
			if len(uidstr) == 3 {
				mapping := uidstr[1] + "+" + uidstr[0] + "+" + uidstr[2]
				mappings = append(mappings, mapping)
			}
		}
		// covert struct IDmappings of rumtime.json to string and check whether is set in container
		for _, um := range ums {
			hostid := strconv.Itoa(int(um.HostID))
			containerid := strconv.Itoa(int(um.ContainerID))
			size := strconv.Itoa(int(um.Size))
			mappingset := hostid + "+" + containerid + "+" + size
			fmt.Println("mappingset=" + mappingset)
			if sort.SearchStrings(mappings, mappingset) == len(mappings) {
				return fmt.Errorf("uidmapping failed: %v ", mappingset)
			}
		}

	}
	return nil
}
