package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/opencontainers/specs"
)

var spec *specs.LinuxSpec
var rspec *specs.LinuxRuntimeSpec

type validation func(*specs.LinuxSpec, *specs.LinuxRuntimeSpec) error

func init() {
	var err error
	spec, rspec, err = loadSpecConfig()
	if err != nil {
		logrus.Fatalf("Failed to load configuration: %q", err)
	}
}

func loadSpecConfig() (spec *specs.LinuxSpec, rspec *specs.LinuxRuntimeSpec, err error) {
	cPath := "config.json"
	cf, err := os.Open(cPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("config.json not found")
		}
	}
	defer cf.Close()

	rPath := "runtime.json"
	rf, err := os.Open(rPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("runtime.json not found")
		}
	}
	defer rf.Close()

	if err = json.NewDecoder(cf).Decode(&spec); err != nil {
		return
	}
	if err = json.NewDecoder(rf).Decode(&rspec); err != nil {
		return
	}
	return spec, rspec, nil
}

func main() {

	app := cli.NewApp()
	app.Name = "oci-runtimeValidate"
	app.Version = "0.0.1"
	app.Usage = "Utilities for OCI runtime validation"
	app.EnableBashCompletion = true

	app.Commands = []cli.Command{
		{
			Name:    "validateOverall",
			Aliases: []string{"va"},
			Usage:   "Validate overall specs",
			Action: func(c *cli.Context) {
				validations := []validation{
					validateProcess,
					validateCapabilities,
					validateHostname,
					validateRlimits,
					validateIDmappings,
					validateSysctls,
					validateRoot,
					validatePlatform,
				}

				for _, v := range validations {
					if err := v(spec, rspec); err != nil {
						logrus.Fatalf("Validation failed: %q", err)
					}
				}
			},
		},
		{
			Name:    "validateIDmappings",
			Aliases: []string{"vid"},
			Usage:   "Validate IDmappings  with specs",
			Action: func(c *cli.Context) {
				if err := validateIDmappings(spec, rspec); err != nil {
					logrus.Fatalf("Validation failed: %q", err)
				}
			},
		},
		{
			Name:    "validatePlatform",
			Aliases: []string{"vpl"},
			Usage:   "Validate Platform  with specs",
			Action: func(c *cli.Context) {
				if err := validatePlatform(spec, rspec); err != nil {
					logrus.Fatalf("Validation failed: %q", err)
				}
			},
		},
		{
			Name:    "validateRoot",
			Aliases: []string{"vro"},
			Usage:   "Validate root  with specs",
			Action: func(c *cli.Context) {
				if err := validateRoot(spec, rspec); err != nil {
					logrus.Fatalf("Validation failed: %q", err)
				}
			},
		},
		{
			Name:    "validateProcess",
			Aliases: []string{"vp"},
			Usage:   "Validate process with specs",
			Action: func(c *cli.Context) {
				if err := validateProcess(spec, rspec); err != nil {
					logrus.Fatalf("Validation failed: %q", err)
				}
			},
		},
		{
			Name:    "validateCapabilities",
			Aliases: []string{"vc"},
			Usage:   "Validate capabilities with specs",
			Action: func(c *cli.Context) {
				if err := validateCapabilities(spec, rspec); err != nil {
					logrus.Fatalf("Validation failed: %q", err)
				}
			},
		},
		{
			Name:    "validateHostname",
			Aliases: []string{"vh"},
			Usage:   "Validate hostname with specs",
			Action: func(c *cli.Context) {
				if err := validateHostname(spec, rspec); err != nil {
					logrus.Fatalf("Validation failed: %q", err)
				}
			},
		},
		{
			Name:    "validateRlimits",
			Aliases: []string{"vr"},
			Usage:   "Validate rlimits with specs",
			Action: func(c *cli.Context) {
				if err := validateRlimits(spec, rspec); err != nil {
					logrus.Fatalf("Validation failed: %q", err)
				}
			},
		},
		{
			Name:    "validateSysctls",
			Aliases: []string{"vs"},
			Usage:   "Validate sysctls with specs",
			Action: func(c *cli.Context) {
				if err := validateSysctls(spec, rspec); err != nil {
					logrus.Fatalf("Validation failed: %q", err)
				}
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		logrus.Fatal(err)
	}

}
