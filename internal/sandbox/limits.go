package sandbox

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Environment variables that override the default Limits.
const (
	EnvTimeout   = "SFW_SANDBOX_TIMEOUT"    // a Go duration, such as 20m
	EnvMemoryMiB = "SFW_SANDBOX_MEMORY_MIB" // RLIMIT_AS of each process
	EnvTmpMiB    = "SFW_SANDBOX_TMP_MIB"    // size of /tmp and RLIMIT_FSIZE
)

// Limits bound one sandboxed run. gVisor's sentry enforces the rlimits
// itself, without cgroups, but per process: the sandbox's processes
// together, and the sentry's own memory, are bounded only by the host.
type Limits struct {
	// Timeout ends the run, which then fails.
	Timeout time.Duration
	// MemoryMiB is each process's address space (RLIMIT_AS). Go maps more
	// than it touches: a deps diff of helm v4 peaks at 8.9 GiB mapped for
	// 7.5 GiB resident.
	MemoryMiB uint64
	// TmpMiB is the size of the /tmp tmpfs, which holds the build cache and
	// a copied signature database, and the largest file a process may
	// write (RLIMIT_FSIZE). tmpfs memory counts toward no rlimit.
	TmpMiB uint64
}

// minMemoryMiB is the least RLIMIT_AS allowed: the Go runtime reserves
// about 600 MiB of address space before main runs.
const minMemoryMiB = 1024

// DefaultLimits are the Limits without overrides. The address space is
// three quarters of the host's memory, so a run fails on its own limit
// before the host's OOM killer takes the machine.
var DefaultLimits = Limits{Timeout: 20 * time.Minute, MemoryMiB: defaultMemoryMiB(), TmpMiB: 2048}

func defaultMemoryMiB() uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 8192
	}
	for _, line := range strings.Split(string(data), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "MemTotal:" {
			if kib, err := strconv.ParseUint(f[1], 10, 64); err == nil {
				return max(kib/1024*3/4, minMemoryMiB)
			}
		}
	}
	return 8192
}

// LimitsFromEnv returns DefaultLimits with the overrides the environment
// sets. A value that does not parse, or is too small, is an error, not the
// default.
func LimitsFromEnv() (Limits, error) {
	l := DefaultLimits
	if v := os.Getenv(EnvTimeout); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return Limits{}, fmt.Errorf("%s=%q: want a positive duration such as 20m", EnvTimeout, v)
		}
		l.Timeout = d
	}
	for _, o := range []struct {
		name string
		min  uint64
		dst  *uint64
	}{{EnvMemoryMiB, minMemoryMiB, &l.MemoryMiB}, {EnvTmpMiB, 1, &l.TmpMiB}} {
		if v := os.Getenv(o.name); v != "" {
			n, err := strconv.ParseUint(v, 10, 32)
			if err != nil || n < o.min {
				return Limits{}, fmt.Errorf("%s=%q: want a number of MiB, at least %d", o.name, v, o.min)
			}
			*o.dst = n
		}
	}
	return l, nil
}

// cpuSeconds is the RLIMIT_CPU of each process: the timeout on every CPU,
// so it ends only a sandbox the timeout failed to kill.
func (l Limits) cpuSeconds() uint64 {
	return uint64(l.Timeout.Seconds()+1) * uint64(runtime.NumCPU())
}

func (l Limits) rlimits() []Rlimit {
	const mib = 1 << 20
	// Soft equals hard: Go ignores SIGXCPU, so only the hard limit's
	// SIGKILL ends a process over its CPU time.
	return []Rlimit{
		{Type: "RLIMIT_NOFILE", Hard: 1024, Soft: 1024},
		{Type: "RLIMIT_AS", Hard: l.MemoryMiB * mib, Soft: l.MemoryMiB * mib},
		{Type: "RLIMIT_CPU", Hard: l.cpuSeconds(), Soft: l.cpuSeconds()},
		{Type: "RLIMIT_FSIZE", Hard: l.TmpMiB * mib, Soft: l.TmpMiB * mib},
	}
}
