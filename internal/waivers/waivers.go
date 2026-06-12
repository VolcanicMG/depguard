// Package waivers persists per-issue suppressions for findings a human has
// reviewed and accepted — the ".guard-ignores" file (DESIGN.md §10, §13).
//
// A waiver does NOT weaken a defense layer: it silences ONE specific finding,
// pinned to an exact name@version + finding-kind, so it stops gating commit /
// push / PR / CI events while still being visible. Because the ID is
// version-pinned, a waiver lapses the moment the package moves to a new version
// — the new version must be evaluated (and, if still unwanted, re-waived) on its
// own. An optional expiry makes a waiver self-retiring; an expired waiver does
// NOT suppress (fail closed) and is reported so it can't rot silently.
//
// The file is committed with the repo (like .guard-approvals) so a waiver — and
// the reason for it — travels to teammates and CI as reviewable evidence.
package waivers

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// FileName lives next to .guardrc / .guard-approvals, committed with the repo.
const FileName = ".guard-ignores"

// dateLayout is the on-disk expiry/added format — a bare calendar day. Waivers
// are a human-scale decision; sub-day precision would be noise in a diff.
const dateLayout = "2006-01-02"

// Entry is one recorded waiver. The map key (in File.Ignores) is the issue ID,
// e.g. "cooldown:lodash@4.17.21" or "advisory:foo@1.2.3:GHSA-xxxx".
type Entry struct {
	// Reason is the free-form justification a human wrote ("vendored fork,
	// vetted"). Optional, but strongly encouraged — it's why this is a
	// purposeful waiver and not a blanket off-switch.
	Reason string `json:"reason,omitempty"`
	// Expires is a "YYYY-MM-DD" calendar day after which the waiver no longer
	// suppresses. Empty means "never expires".
	Expires string `json:"expires,omitempty"`
	// Added is the day the waiver was recorded (audit trail in code review).
	Added string `json:"added"`
}

// File is the on-disk .guard-ignores structure.
type File struct {
	Schema  int              `json:"schema"`
	Ignores map[string]Entry `json:"ignores"`
}

// Load reads dir/.guard-ignores; a missing file is an empty (not error) state,
// so every command works in a repo that has never waived anything.
func Load(dir string) (*File, error) {
	f := &File{Schema: 1, Ignores: map[string]Entry{}}
	data, err := os.ReadFile(dir + "/" + FileName)
	if err != nil {
		if os.IsNotExist(err) {
			return f, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, f); err != nil {
		return nil, err
	}
	if f.Ignores == nil {
		f.Ignores = map[string]Entry{}
	}
	return f, nil
}

// Status is the result of testing a finding's ID against the waivers.
type Status int

const (
	// None: no waiver exists for this ID — the finding gates normally.
	None Status = iota
	// Active: a waiver exists and is in force — the finding is suppressed.
	Active
	// Expired: a waiver exists but its expiry has passed — it does NOT suppress
	// (fail closed); the finding gates again and the stale waiver is reported.
	Expired
)

// Check reports how id is treated: not waived, actively waived, or waived by a
// lapsed (expired) entry. The Entry is returned for Active/Expired so callers
// can show the reason. now is injected so the same logic is testable and so a
// single `guard check` sees one consistent "today".
func (f *File) Check(id string, now time.Time) (Entry, Status) {
	e, ok := f.Ignores[id]
	if !ok {
		return Entry{}, None
	}
	if e.Expires == "" {
		return e, Active
	}
	exp, err := time.Parse(dateLayout, e.Expires)
	if err != nil {
		// A malformed expiry is treated as already-expired: fail closed rather
		// than trust an unparseable date to keep suppressing a real finding.
		return e, Expired
	}
	// The waiver is valid THROUGH its expiry day (inclusive); it lapses once the
	// calendar has moved past that day.
	if now.Truncate(24 * time.Hour).After(exp) {
		return e, Expired
	}
	return e, Active
}

// Set records (or replaces) a waiver for id. expires is "" for never, a
// "YYYY-MM-DD" absolute day, or a relative "<N>d" span resolved against today.
// Returns an error on an unparseable expiry so a typo can't silently become
// "never expires".
func (f *File) Set(id, reason, expires string) error {
	abs, err := normalizeExpiry(expires, time.Now())
	if err != nil {
		return err
	}
	f.Ignores[id] = Entry{
		Reason:  reason,
		Expires: abs,
		Added:   time.Now().UTC().Format(dateLayout),
	}
	return nil
}

// Remove deletes a waiver; reports whether one was present.
func (f *File) Remove(id string) bool {
	if _, ok := f.Ignores[id]; !ok {
		return false
	}
	delete(f.Ignores, id)
	return true
}

// IDs returns the waiver keys sorted, for stable listing.
func (f *File) IDs() []string {
	ids := make([]string, 0, len(f.Ignores))
	for id := range f.Ignores {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Save writes the file with stable, indented JSON — these are security
// decisions and should diff cleanly in code review.
func (f *File) Save(dir string) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(dir+"/"+FileName, append(data, '\n'), 0o644)
}

// normalizeExpiry turns user input into the stored "YYYY-MM-DD" form. Accepts
// "" (never), "<N>d" (relative to now), or an absolute "YYYY-MM-DD".
func normalizeExpiry(s string, now time.Time) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n <= 0 {
			return "", fmt.Errorf("bad expiry %q (want <N>d or YYYY-MM-DD)", s)
		}
		return now.AddDate(0, 0, n).Format(dateLayout), nil
	}
	if _, err := time.Parse(dateLayout, s); err != nil {
		return "", fmt.Errorf("bad expiry %q (want <N>d or YYYY-MM-DD)", s)
	}
	return s, nil
}
