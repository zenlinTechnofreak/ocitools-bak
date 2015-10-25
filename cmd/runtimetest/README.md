# runtimetest

This repo provide a runtimetest tool to do runtime validation about the compliance with specs,      
it is the container end test programme, Follow bellow steps to use it,      
       
      - Create a bundle with rootfs and configs
      - Move the runtimetest to root path of rootfs
      - Run the container with the bundle


```
NAME:
   oci-runtimeValidate

USAGE:
   ./runtimetest [global options] command [command options] [arguments...]
   
VERSION:
   0.0.1
   
COMMANDS:
   validateProcess, vp		Validate process with specs
   validateCapabilities, vc	Validate capabilities with specs
   validateHostname, vh		Validate hostname with specs
   validateRlimits, vr		Validate rlimits with specs
   validateSysctls, vs		Validate sysctls with specs
   help, h			Shows a list of commands or help for one command
   
GLOBAL OPTIONS:
   --help, -h			show help
   --generate-bash-completion	
   --version, -v			print the version

```
