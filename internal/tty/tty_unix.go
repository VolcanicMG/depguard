//go:build linux || darwin

// Package tty answers one question: is a human attached to a stream?
//
// The naive os.ModeCharDevice check is wrong — /dev/null is a char device,
// so CI pipes and `< /dev/null` would look "interactive" and depguard would
// burn its one prompt on an EOF, recording a denial no human made. The real
// test is whether the fd speaks termios.
package tty

import (
	"os"
	"syscall"
	"unsafe"
)

// IsTerminal reports whether stdin is an actual terminal (the human-attached
// gate for the approval prompt).
func IsTerminal() bool { return IsTerminalFd(os.Stdin.Fd()) }

// IsTerminalFd reports whether the given file descriptor is a real terminal
// (termios ioctl succeeds), not merely a character device. Used for stdin
// (prompt gating) and for stdout/stderr (color gating in internal/ui).
func IsTerminalFd(fd uintptr) bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL,
		fd, ioctlReadTermios,
		uintptr(unsafe.Pointer(&t)), 0, 0, 0)
	return errno == 0
}
