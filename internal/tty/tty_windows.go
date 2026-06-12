//go:build windows

package tty

import "os"

// IsTerminal on Windows falls back to the char-device check. Imperfect (NUL
// is a char device there too), but Windows CI runners are rare for this tool
// and the failure mode is a skipped prompt, never an auto-approval.
func IsTerminal() bool { return IsTerminalFd(os.Stdin.Fd()) }

// IsTerminalFd is the fd-taking variant (parity with the unix build) used for
// color gating on stdout/stderr.
func IsTerminalFd(fd uintptr) bool {
	f := os.NewFile(fd, "")
	if f == nil {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
