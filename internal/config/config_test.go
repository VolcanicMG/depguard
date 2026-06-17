package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"depguard/internal/advisory"
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

// TestAdvisoryThresholdDefault confirms the default policy blocks at high.
func TestAdvisoryThresholdDefault(t *testing.T) {
	if got := Defaults().AdvisoryThreshold; got != advisory.SevHigh {
		t.Errorf("default AdvisoryThreshold = %v, want high", got)
	}
	// An un-init'ed repo (no .guardrc) must also get the default.
	c, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if c.AdvisoryThreshold != advisory.SevHigh {
		t.Errorf("Load(no file) AdvisoryThreshold = %v, want high", c.AdvisoryThreshold)
	}
}

// TestAdvisoryThresholdParsed covers a valid override.
func TestAdvisoryThresholdParsed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte("advisory-threshold: moderate\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.AdvisoryThreshold != advisory.SevModerate {
		t.Errorf("AdvisoryThreshold = %v, want moderate", c.AdvisoryThreshold)
	}
}

// TestAdvisoryThresholdRejectsTypo is the fail-closed case: a typo'd level must
// error, not silently arm an unknown threshold.
func TestAdvisoryThresholdRejectsTypo(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte("advisory-threshold: hgh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Error("Load accepted 'advisory-threshold: hgh'; expected an error")
	}
}

// TestAdvisoryThresholdCanonicalValue confirms SetValue normalizes and rejects.
func TestAdvisoryThresholdCanonicalValue(t *testing.T) {
	if got, err := canonicalValue("advisory-threshold", "CRITICAL"); err != nil || got != "critical" {
		t.Errorf("canonicalValue(critical) = (%q,%v), want (critical,nil)", got, err)
	}
	if _, err := canonicalValue("advisory-threshold", "nope"); err == nil {
		t.Error("canonicalValue accepted a bad threshold; expected an error")
	}
}
