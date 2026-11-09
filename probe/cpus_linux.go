//go:build linux

package probe

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// onlinePath lists the CPUs the kernel has online, a subset of the possible
// ones, which VMs with hotplug slots advertise many more of
const onlinePath = "/sys/devices/system/cpu/online"

// readOnline returns the CPUs online now, tests replace it
var readOnline = func() ([]int, error) {
	// a container's own view of the file, as lxcfs mounts over sysfs, lists the
	// CPUs of its cpuset while the programs run on every CPU of the host
	var fs unix.Statfs_t
	if err := unix.Statfs(onlinePath, &fs); err != nil {
		return nil, err
	}
	if fs.Type != unix.SYSFS_MAGIC {
		return nil, fmt.Errorf("%s is not on sysfs", onlinePath)
	}
	b, err := os.ReadFile(onlinePath)
	if err != nil {
		return nil, err
	}
	return parseCPUList(string(b))
}
