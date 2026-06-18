// Package freshness re-verifies the cooldown on versions that are ALREADY in
// the lockfile — the enforcement layer for installs that never went through
// `guard install` (plain npm, npx, a teammate without depguard, npm ci).
//
// The proxy can only filter installs routed through it; this check, run by
// the pre-commit hook and CI gate, catches everything else at the repo
// boundary: a too-young version can land in node_modules, but it can't land
// in the shared history without a human seeing the violation.
package freshness

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"depguard/internal/lockfile"
	"depguard/internal/semver"
)

// Violation is one lockfile version still inside the cooldown window.
type Violation struct {
	Name    string
	Version string
	// Age is time since publish; zero when the registry had no timestamp.
	Age time.Duration
	// Remaining is how much longer until this version clears the cooldown
	// (cooldown − Age). Zero when the publish date is unknown (we can't tell
	// when it clears, so it's treated as fail-closed with no ETA).
	Remaining time.Duration
}

// workers bounds concurrent packument fetches: each is one registry GET and
// commits typically add a handful of versions, but a first-ever check can
// cover a whole tree.
const workers = 8

// Check fetches publish times for each name@version and returns the ones
// younger than cooldown. skip lets the caller exempt allowlisted packages.
// Network errors per package are returned as warnings (fail-open: a registry
// blip must not block every commit; the loud warning is the compromise).
func Check(registry string, pkgs []lockfile.Pkg, cooldown time.Duration, skip func(string) bool) ([]Violation, []string) {
	type job struct{ name, version string }
	jobs := make(chan job)
	var mu sync.Mutex
	var violations []Violation
	var warnings []string
	client := &http.Client{Timeout: 30 * time.Second}
	cutoff := time.Now().Add(-cooldown)

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				published, err := publishTime(client, registry, j.name, j.version)
				mu.Lock()
				switch {
				case err != nil:
					warnings = append(warnings, fmt.Sprintf("%s@%s: %v", j.name, j.version, err))
				case published.IsZero():
					// No timestamp: same fail-closed stance as the proxy. No
					// publish date means no ETA, so Remaining stays zero.
					violations = append(violations, Violation{Name: j.name, Version: j.version})
				case published.After(cutoff):
					age := time.Since(published)
					violations = append(violations, Violation{
						Name: j.name, Version: j.version, Age: age, Remaining: cooldown - age,
					})
				}
				mu.Unlock()
			}
		}()
	}
	for _, p := range pkgs {
		if skip != nil && skip(p.Name) {
			continue
		}
		jobs <- job{p.Name, p.Version}
	}
	close(jobs)
	wg.Wait()
	return violations, warnings
}

// publishTime fetches one package's time map and returns the publish time of
// the given version. Zero time + nil error means the registry has no
// timestamp for that version.
func publishTime(client *http.Client, registry, name, version string) (time.Time, error) {
	resp, err := client.Get(registry + "/" + url.PathEscape(name))
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("registry returned %d", resp.StatusCode)
	}
	// Decode only the time map; the rest of the packument (potentially MBs)
	// is skipped by the decoder.
	var doc struct {
		Time map[string]string `json:"time"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return time.Time{}, fmt.Errorf("packument parse: %w", err)
	}
	s, ok := doc.Time[version]
	if !ok {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, nil
	}
	return t, nil
}

// LatestSafe returns the highest STABLE version of name whose publish age is at
// least cooldown — the newest version an install could safely pin to in place of
// a too-fresh one (the `guard check --confirm` "pin & reinstall" path). Returns
// "" (nil error) when the registry exposes no qualifying version; a network or
// parse error is returned so the caller can fall back to a generic message
// instead of a bogus suggestion.
func LatestSafe(registry, name string, cooldown time.Duration) (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(registry + "/" + url.PathEscape(name))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry returned %d", resp.StatusCode)
	}
	// Decode the version set + the time map; tarball/dist blobs are skipped.
	var doc struct {
		Versions map[string]json.RawMessage `json:"versions"`
		Time     map[string]string          `json:"time"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("packument parse: %w", err)
	}
	cutoff := time.Now().Add(-cooldown)
	var safe []string
	for v := range doc.Versions {
		ts, ok := doc.Time[v]
		if !ok {
			continue // no publish timestamp → can't prove it cleared cooldown
		}
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil || t.After(cutoff) {
			continue // unparseable or still inside the window
		}
		safe = append(safe, v)
	}
	return semver.MaxStable(safe), nil
}
