// Package ui is depguard's tiny, zero-dependency terminal-color helper.
//
// Color is a readability aid, never information: every glyph and label is the
// same word with or without it, so a piped or NO_COLOR session loses nothing.
// It is emitted ONLY when NO_COLOR is unset AND both stdout and stderr are real
// terminals — requiring both means redirecting either stream (`guard status >
// file`, `guard check | tee`) never leaks escape codes into the captured text.
package ui

import (
	"os"

	"depguard/internal/tty"
)

// enabled is computed once at startup (the stream identities don't change
// mid-process). See the package doc for the policy.
var enabled = os.Getenv("NO_COLOR") == "" &&
	tty.IsTerminalFd(os.Stdout.Fd()) &&
	tty.IsTerminalFd(os.Stderr.Fd())

// SetEnabled overrides the auto-detected state (tests, or a future --color flag).
func SetEnabled(on bool) { enabled = on }

// Enabled reports whether color output is currently on.
func Enabled() bool { return enabled }

// paint wraps s in an SGR code when color is enabled, otherwise returns s as-is.
func paint(code, s string) string {
	if !enabled {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// Semantic status glyphs — the vocabulary the rest of the CLI scans by.
func OK() string     { return paint("32", "✓") } // green  — passed / healthy
func Warn() string   { return paint("33", "⚠") } // yellow — attention, not a failure
func Bad() string    { return paint("31", "✗") } // red    — failed / convicted
func Waived() string { return paint("36", "⊘") } // cyan   — suppressed by a waiver

// Text colorizers for the status report and labels.
func Green(s string) string  { return paint("32", s) }
func Yellow(s string) string { return paint("33", s) }
func Red(s string) string    { return paint("31", s) }
func Dim(s string) string    { return paint("2", s) }
func Bold(s string) string   { return paint("1", s) }
