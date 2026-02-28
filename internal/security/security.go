package security

import (
	"os/exec"
	"syscall"
)

type SecurityOptions struct {
	MaxCPU       int
	MaxMemory    int
	MaxNetwork   bool
	ReadOnlyFS   bool
	AllowedDirs  []string
	NoPrivileges bool
}

func DefaultSecurityOptions() *SecurityOptions {
	return &SecurityOptions{
		MaxCPU:       30,
		MaxMemory:    100,
		MaxNetwork:   true,
		ReadOnlyFS:   false,
		AllowedDirs:  []string{},
		NoPrivileges: true,
	}
}

func ApplySecurityOptions(cmd *exec.Cmd, options *SecurityOptions) {
	if options.MaxCPU > 0 || options.MaxMemory > 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	if options.NoPrivileges {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
}
