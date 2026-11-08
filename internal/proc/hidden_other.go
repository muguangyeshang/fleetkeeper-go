//go:build !windows

package proc

import "syscall"

// hiddenAttr is a no-op outside Windows: POSIX has no console window
// concept, and the POSIX branch of Restart/stop uses plain exec.
func hiddenAttr() *syscall.SysProcAttr { return nil }
