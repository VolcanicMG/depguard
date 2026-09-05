package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// TestSecretPathsParsed verifies the secret-paths list key loads into config.
func TestSecretPathsParsed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(`secret-paths: [".env", ".env.*", "secrets/"]`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{".env", ".env.*", "secrets/"}
	if len(c.SecretPaths) != len(want) {
		t.Fatalf("SecretPaths = %v, want %v", c.SecretPaths, want)
	}
	for i := range want {
		if c.SecretPaths[i] != want[i] {
			t.Fatalf("SecretPaths[%d] = %q, want %q", i, c.SecretPaths[i], want[i])
		}
	}
}

// TestSecretPathsCanonicalValue verifies guard config set normalizes the list.
func TestSecretPathsCanonicalValue(t *testing.T) {
	got, err := canonicalValue("secret-paths", ".env, secrets/  *.pem")
	if err != nil {
		t.Fatalf("canonicalValue: %v", err)
	}
	if got != `[.env, secrets/, *.pem]` {
		t.Fatalf("canonicalValue = %q, want [.env, secrets/, *.pem]", got)
	}
}

// TestSecretPathsDefaultEmpty: the gate is off by default (no .guardrc).
func TestSecretPathsDefaultEmpty(t *testing.T) {
	c, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(c.SecretPaths) != 0 {
		t.Fatalf("default SecretPaths = %v, want empty", c.SecretPaths)
	}
}

// TestAddSecretPathAppendsAndDedups verifies the append command grows the list
// without restating it, and ignores a duplicate.
func TestAddSecretPathAppendsAndDedups(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(`secret-paths: [".env"]`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// New pattern → appended.
	added, err := AddSecretPath(dir, "secrets/")
	if err != nil || !added {
		t.Fatalf("AddSecretPath(secrets/) = (%v, %v), want (true, nil)", added, err)
	}
	// Duplicate → no-op.
	added, err = AddSecretPath(dir, ".env")
	if err != nil || added {
		t.Fatalf("AddSecretPath(.env dup) = (%v, %v), want (false, nil)", added, err)
	}
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{".env", "secrets/"}
	if len(c.SecretPaths) != len(want) {
		t.Fatalf("SecretPaths = %v, want %v", c.SecretPaths, want)
	}
	for i := range want {
		if c.SecretPaths[i] != want[i] {
			t.Fatalf("SecretPaths[%d] = %q, want %q", i, c.SecretPaths[i], want[i])
		}
	}
}

// TestAddSecretPathFromEmpty: creating the key when no secret-paths line exists.
func TestAddSecretPathFromEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte("cooldown: 14d\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if added, err := AddSecretPath(dir, "*.pem"); err != nil || !added {
		t.Fatalf("AddSecretPath from empty = (%v, %v), want (true, nil)", added, err)
	}
	c, _ := Load(dir)
	if len(c.SecretPaths) != 1 || c.SecretPaths[0] != "*.pem" {
		t.Fatalf("SecretPaths = %v, want [*.pem]", c.SecretPaths)
	}
}

// on-check-error decides whether a check that could NOT run is a warning or a
// gate. It must parse both values, default to warn, and fail closed on a typo —
// a mistyped security toggle must never silently pick the looser mode.
func TestOnCheckErrorParse(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) Config {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, FileName), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		c, err := Load(dir)
		if err != nil {
			t.Fatalf("Load(%q): %v", body, err)
		}
		return c
	}
	if Defaults().OnCheckErrorFail {
		t.Error("default OnCheckErrorFail = true, want warn (fail-open) by default")
	}
	if !write("on-check-error: fail\n").OnCheckErrorFail {
		t.Error("on-check-error: fail did not set OnCheckErrorFail")
	}
	if write("on-check-error: warn\n").OnCheckErrorFail {
		t.Error("on-check-error: warn set OnCheckErrorFail")
	}
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte("on-check-error: yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Error("a bogus on-check-error value was accepted — must fail closed")
	}
	// And the editing path must agree with Load about what's legal.
	if _, err := canonicalValue("on-check-error", "fail"); err != nil {
		t.Errorf("canonicalValue rejected a legal value: %v", err)
	}
	if _, err := canonicalValue("on-check-error", "nope"); err == nil {
		t.Error("canonicalValue accepted an illegal on-check-error value")
	}
}

// Degrade is the single decision point for every fail-open lookup in the repo:
// warn returns nil (work continues), fail returns the error (the gate trips).
func TestDegrade(t *testing.T) {
	boom := errors.New("osv unreachable")
	if err := (Config{}).Degrade("advisory check", boom); err != nil {
		t.Errorf("warn mode gated: %v", err)
	}
	// The warning is NOT suppressible: the hooks pass --quiet, and a silent
	// fail-open is exactly what the degraded-reporting stance exists to prevent.
	err := Config{OnCheckErrorFail: true}.Degrade("advisory check", boom)
	if err == nil {
		t.Fatal("fail mode did not gate a check that could not complete")
	}
	if !strings.Contains(err.Error(), "advisory check") || !strings.Contains(err.Error(), "osv unreachable") {
		t.Errorf("error = %q, want it to name the check and the cause", err)
	}
	// No error means nothing to report, in either mode.
	if err := (Config{OnCheckErrorFail: true}).Degrade("advisory check", nil); err != nil {
		t.Errorf("Degrade(nil) = %v, want nil", err)
	}
}
