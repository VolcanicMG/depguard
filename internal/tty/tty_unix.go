//go:build linux || darwin

// Package tty answers one question: is a human attached to stdin?
//
// The naive os.ModeCharDevice check is wrong — /dev/null is a char device,
// so CI pipes and `< /dev/null` would look "interactive" and depguard would
// burn its one prompt on an EOF, recording a denial no human made. The real
// test is whether stdin speaks termios.
package tty

import (
	"os"
	"syscall"
	"unsafe"
)

// IsTerminal reports whether stdin is an actual terminal (termios ioctl
// succeeds), not merely a character device.
func IsTerminal() bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL,
		os.Stdin.Fd(), ioctlReadTermios,
		uintptr(unsafe.Pointer(&t)), 0, 0, 0)
	return errno == 0
}
