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
	gms := rspec.Linux.GIDMappings
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
			if sort.SearchStrings(mappings, mappingset) == len(mappings) {
				return fmt.Errorf("uidmapping failed: %v ", mappingset)
			}
		}
	}
	if gms != nil {
		out, _ := ioutil.ReadFile("/proc/1/gid_map")
		gidbytes := bytes.Split(out, []byte{'\n'})
		mappings := []string{}
		//convert the content of /proc/1/gid_map to stringslice
		// and each line in the file convert to string ,Formmat:HostID+ContainerID+Size
		for _, gidbyte := range gidbytes {
			gidstr := strings.Fields(string(gidbyte))
			if len(gidstr) == 3 {
				mapping := gidstr[1] + "+" + gidstr[0] + "+" + gidstr[2]
				mappings = append(mappings, mapping)
			}
		}
		// covert struct IDmappings of rumtime.json to string and check whether is set in container
		for _, gm := range gms {
			hostid := strconv.Itoa(int(gm.HostID))
			containerid := strconv.Itoa(int(gm.ContainerID))
			size := strconv.Itoa(int(gm.Size))
			mappingset := hostid + "+" + containerid + "+" + size
			if sort.SearchStrings(mappings, mappingset) == len(mappings) {
				return fmt.Errorf("gidmapping failed: %v ", mappingset)
			}
		}

	}
	return nil
}
