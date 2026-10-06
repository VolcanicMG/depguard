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
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"depguard/internal/lockfile"
	"depguard/internal/semver"
)

// maxPackumentBytes caps bytes read from a registry packument. Generous —
// real ones reach tens of MB; it only stops an endless body from a hostile or
// MITM'd registry. Truncation surfaces as a decode error, so we fail closed.
// var so a test can lower it cheaply.
var maxPackumentBytes int64 = 128 << 20 // 128 MiB

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
	type job struct{ eco, name, version string }
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
				published, err := publishTime(client, registry, j.eco, j.name, j.version)
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
		jobs <- job{p.Ecosystem, p.Name, p.Version}
	}
	close(jobs)
	wg.Wait()
	return violations, warnings
}

// publishTime fetches one package's time map and returns the publish time of
// the given version. Zero time + nil error means the registry has no
// timestamp for that version. eco "pypi" reads PyPI's JSON API instead.
func publishTime(client *http.Client, registry, eco, name, version string) (time.Time, error) {
	if eco == "pypi" {
		return pypiPublishTime(client, registry, name, version)
	}
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxPackumentBytes)).Decode(&doc); err != nil {
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
//
// eco "pypi" treats registry as the PyPI base and picks among PyPI releases.
func LatestSafe(registry, eco, name string, cooldown time.Duration) (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	if eco == "pypi" {
		return pypiLatestSafe(client, registry, name, cooldown)
	}
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxPackumentBytes)).Decode(&doc); err != nil {
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

// pypiFile is the slice of a PyPI JSON-API release file we read.
type pypiFile struct {
	Uploaded string `json:"upload_time_iso_8601"`
}

// pypiGet fetches and decodes one PyPI JSON-API document (capped like a packument).
func pypiGet(client *http.Client, u string, into any) error {
	resp, err := client.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pypi returned %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxPackumentBytes)).Decode(into); err != nil {
		return fmt.Errorf("pypi json parse: %w", err)
	}
	return nil
}

// earliestUpload is a release's publish time: its FIRST uploaded file. A later
// wheel added to an old release doesn't make the release young. Zero when no
// file carries a parseable timestamp.
func earliestUpload(files []pypiFile) time.Time {
	var first time.Time
	for _, f := range files {
		t, err := time.Parse(time.RFC3339, f.Uploaded)
		if err == nil && (first.IsZero() || t.Before(first)) {
			first = t
		}
	}
	return first
}

// pypiPublishTime is publishTime for PyPI: GET {base}/pypi/<name>/<version>/json.
func pypiPublishTime(client *http.Client, base, name, version string) (time.Time, error) {
	var doc struct {
		URLs []pypiFile `json:"urls"`
	}
	if err := pypiGet(client, base+"/pypi/"+url.PathEscape(name)+"/"+url.PathEscape(version)+"/json", &doc); err != nil {
		return time.Time{}, err
	}
	return earliestUpload(doc.URLs), nil
}

// pypiLatestSafe is LatestSafe for PyPI: the highest stable release (digits and
// dots only — no pre/dev/post/local) whose earliest upload is past the cooldown.
func pypiLatestSafe(client *http.Client, base, name string, cooldown time.Duration) (string, error) {
	var doc struct {
		Releases map[string][]pypiFile `json:"releases"`
	}
	if err := pypiGet(client, base+"/pypi/"+url.PathEscape(name)+"/json", &doc); err != nil {
		return "", err
	}
	cutoff := time.Now().Add(-cooldown)
	best := ""
	for v, files := range doc.Releases {
		t := earliestUpload(files)
		if !pyStable(v) || t.IsZero() || t.After(cutoff) {
			continue
		}
		if best == "" || pyLess(best, v) {
			best = v
		}
	}
	return best, nil
}

// pyStable reports a plain release version: dot-separated digit runs only.
func pyStable(v string) bool {
	for _, part := range strings.Split(v, ".") {
		if part == "" || strings.Trim(part, "0123456789") != "" {
			return false
		}
	}
	return true
}

// pyLess compares two pyStable versions numerically, missing parts as 0
// (PEP 440: 1.0 == 1.0.0).
func pyLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x < y
		}
	}
	return false
}
