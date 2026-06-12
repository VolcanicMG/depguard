package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseDaysRejectsNegative(t *testing.T) {
	for _, s := range []string{"-1d", "-30d", "-3h"} {
		if _, err := parseDays(s); err == nil {
			t.Errorf("parseDays(%q) returned nil; a negative cooldown silently disables the filter and must be rejected", s)
		}
	}
}

func TestParseDaysValid(t *testing.T) {
	cases := map[string]time.Duration{
		"14d":  14 * 24 * time.Hour,
		"0d":   0, // "off" is allowed; negative is not
		"1d":   24 * time.Hour,
		"336h": 336 * time.Hour,
	}
	for s, want := range cases {
		got, err := parseDays(s)
		if err != nil {
			t.Errorf("parseDays(%q) error: %v", s, err)
			continue
		}
		if got != want {
			t.Errorf("parseDays(%q) = %v, want %v", s, got, want)
		}
	}
}

// TestLoadRejectsNegativeCooldown confirms the rejection reaches the public path.
func TestLoadRejectsNegativeCooldown(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte("cooldown: -1d\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Error("Load accepted 'cooldown: -1d'; expected an error")
	}
}
