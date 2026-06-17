// Package advisory checks installed versions against the OSV.dev database —
// Layer 5's "did something I already installed turn out to be bad?" feed
// (DESIGN.md §3, §5). Used by `guard check`, which the git hooks and CI run.
package advisory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"depguard/internal/lockfile"
)

// Severity is an advisory's normalized blast level. SevUnknown is the ZERO
// value on purpose: an advisory we could not score (or a Vuln nobody enriched)
// reads as unknown and fails closed — it blocks (DESIGN.md §5). Low..Critical
// are ordered so a numeric ">= threshold" comparison answers "does this gate?".
type Severity int

const (
	// SevUnknown (zero value): OSV carried no machine-readable severity for this
	// id, or the Vuln was never enriched. Always blocks (handled in Blocks).
	SevUnknown Severity = iota
	// SevLow..SevCritical mirror the GHSA/npm labels OSV reports in
	// database_specific.severity. The order is what the threshold compares.
	SevLow
	SevModerate
	SevHigh
	SevCritical
)

// String renders the severity for human output and config round-trips.
func (s Severity) String() string {
	switch s {
	case SevLow:
		return "low"
	case SevModerate:
		return "moderate"
	case SevHigh:
		return "high"
	case SevCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ParseSeverity maps a label (GHSA "CRITICAL"/"HIGH"/"MODERATE"/"LOW", case-
// insensitive) to a Severity. Anything unrecognized — including "" — is
// SevUnknown. ok reports whether the label was a recognized level, so config
// parsing can reject a typo instead of silently arming an unknown threshold.
func ParseSeverity(s string) (Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low":
		return SevLow, true
	case "moderate", "medium":
		return SevModerate, true
	case "high":
		return SevHigh, true
	case "critical":
		return SevCritical, true
	default:
		return SevUnknown, false
	}
}

// Vuln is one advisory hit on an installed package version.
type Vuln struct {
	Package  string
	Version  string
	ID       string // OSV/GHSA id, e.g. GHSA-xxxx or MAL-2024-xxxx
	Summary  string
	Severity Severity // populated by Severities(); SevUnknown until enriched
}

// Blocks reports whether this hit should gate the action (vs. warn only) under
// the given threshold. Two things always block regardless of threshold: a MAL-*
// id (a package OSV flags as outright malicious — the tool's whole reason to
// exist, never downgradable to a warning) and an unknown/unscored severity
// (fail closed — we can't prove it's minor). Otherwise it blocks at or above
// the threshold and warns below it.
func (v Vuln) Blocks(threshold Severity) bool {
	if strings.HasPrefix(v.ID, "MAL-") {
		return true
	}
	if v.Severity == SevUnknown {
		return true
	}
	return v.Severity >= threshold
}

// osvBatchURL is OSV's bulk endpoint: one POST covers a whole lockfile.
// var (not const) so a test can repoint it at a local httptest server.
var osvBatchURL = "https://api.osv.dev/v1/querybatch"

// osvVulnURL is OSV's per-vuln detail endpoint. querybatch returns only ids, so
// severity (database_specific.severity / CVSS label) requires this extra GET per
// distinct id. var (not const) so a test can repoint it at an httptest server.
var osvVulnURL = "https://api.osv.dev/v1/vulns/"

// maxSeverityFetches caps how many distinct ids Severities() will enrich, so a
// pathological lockfile with thousands of hits can't fan out into thousands of
// requests. Beyond the cap, ids stay SevUnknown — which BLOCKS under the
// fail-closed policy, so the cap never weakens the gate. var for tests.
var maxSeverityFetches = 256

// batchSize stays under OSV's request limits while keeping round-trips low.
const batchSize = 500

// maxOSVResponse caps bytes read from OSV's response. A compromised or MITM'd
// endpoint can't exhaust memory with an unbounded JSON stream; a batch answer
// for 500 queries is well under this.
var maxOSVResponse int64 = 32 << 20 // 32 MiB (var so a test can lower it)

// CheckVersions queries OSV for several versions of ONE package and returns
// the versions that carry at least one advisory, mapped to the first hit's id.
// Used by the proxy to drop known-bad versions at resolve time (avoid, not
// just recover).
func CheckVersions(name string, versions []string) (map[string]string, error) {
	pkgs := make([]lockfile.Pkg, len(versions))
	for i, v := range versions {
		pkgs[i] = lockfile.Pkg{Name: name, Version: v}
	}
	vulns, err := Check(pkgs)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, vu := range vulns {
		if _, ok := out[vu.Version]; !ok {
			out[vu.Version] = vu.ID
		}
	}
	return out, nil
}

// Check queries OSV for every name@version pair and returns the hits.
// pkgs is the distinct set of installed versions — every version is queried,
// including multiple versions of the same name (see lockfile.Pkg).
func Check(pkgs []lockfile.Pkg) ([]Vuln, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	var vulns []Vuln

	for start := 0; start < len(pkgs); start += batchSize {
		end := min(start+batchSize, len(pkgs))
		chunk := pkgs[start:end]

		// Build the querybatch payload for this chunk.
		queries := make([]map[string]any, len(chunk))
		for i, r := range chunk {
			queries[i] = map[string]any{
				"package": map[string]string{"name": r.Name, "ecosystem": "npm"},
				"version": r.Version,
			}
		}
		body, err := json.Marshal(map[string]any{"queries": queries})
		if err != nil {
			return nil, err
		}

		resp, err := client.Post(osvBatchURL, "application/json", bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("osv query: %w", err)
		}
		// Fail LOUD on a non-200. OSV is a security gate (the hooks/CI block on
		// its verdict); a 429 (rate-limit) or 5xx must surface as an error, not
		// decode to an empty result set that reads as "no advisories" — that
		// would let an OSV outage or a rate-limit quietly turn the gate green.
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("osv query: unexpected status %d", resp.StatusCode)
		}
		var parsed struct {
			Results []struct {
				Vulns []struct {
					ID      string `json:"id"`
					Summary string `json:"summary"`
				} `json:"vulns"`
			} `json:"results"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, maxOSVResponse)).Decode(&parsed)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("osv response: %w", err)
		}
		// Results are positional: results[i] answers queries[i].
		for i, res := range parsed.Results {
			for _, v := range res.Vulns {
				vulns = append(vulns, Vuln{
					Package: chunk[i].Name,
					Version: chunk[i].Version,
					ID:      v.ID,
					Summary: v.Summary,
				})
			}
		}
	}
	return vulns, nil
}

// Severities fetches each DISTINCT id's detail record from OSV and returns a
// map id -> Severity. It is the enrichment step the gating path runs AFTER
// Check (querybatch carries no severity); the proxy's resolve-time path does
// NOT call it, keeping version filtering to one round-trip.
//
// Fail-open per id: a network error or a record with no machine-readable
// severity leaves that id absent from the map, which the caller reads as
// SevUnknown — and SevUnknown BLOCKS. So a flaky OSV detail fetch can only make
// the gate stricter, never let a hit through unscored.
func Severities(ids []string) map[string]Severity {
	out := make(map[string]Severity, len(ids))
	client := &http.Client{Timeout: 30 * time.Second}
	seen := map[string]bool{}
	fetched := 0
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		if fetched >= maxSeverityFetches {
			break // remaining ids stay SevUnknown -> block (fail closed)
		}
		fetched++
		sev, ok := fetchSeverity(client, id)
		if ok {
			out[id] = sev
		}
	}
	return out
}

// fetchSeverity GETs one OSV vuln record and extracts its severity. It reads
// database_specific.severity first (GHSA's "CRITICAL"/"HIGH"/"MODERATE"/"LOW",
// the label npm itself uses); failing that, a CVSS entry whose score is a bare
// label (some feeds populate it that way). A CVSS *vector* string is NOT scored
// here — computing a base score is out of scope for a zero-dep build, and an
// unscored hit blocks anyway. ok is false on any error or no usable label.
func fetchSeverity(client *http.Client, id string) (Severity, bool) {
	resp, err := client.Get(osvVulnURL + id)
	if err != nil {
		return SevUnknown, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return SevUnknown, false
	}
	var d struct {
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxOSVResponse)).Decode(&d); err != nil {
		return SevUnknown, false
	}
	if s, ok := ParseSeverity(d.DatabaseSpecific.Severity); ok {
		return s, true
	}
	for _, sv := range d.Severity {
		if s, ok := ParseSeverity(sv.Score); ok {
			return s, true
		}
	}
	return SevUnknown, false
}
