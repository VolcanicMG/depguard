//go:build windows

package tty

import "os"

// IsTerminal on Windows falls back to the char-device check. Imperfect (NUL
// is a char device there too), but Windows CI runners are rare for this tool
// and the failure mode is a skipped prompt, never an auto-approval.
func IsTerminal() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
