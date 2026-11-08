//go:build windows

package proc

import "syscall"

// hiddenAttr returns the Windows-only attributes: no console window
// for the restart/stop child, plus CREATE_NO_WINDOW.
func hiddenAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}
