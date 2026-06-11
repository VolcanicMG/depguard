// Package advisory checks installed versions against the OSV.dev database —
// Layer 5's "did something I already installed turn out to be bad?" feed
// (DESIGN.md §3, §5). Used by `guard check`, which the git hooks and CI run.
package advisory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"depguard/internal/lockfile"
)

// Vuln is one advisory hit on an installed package version.
type Vuln struct {
	Package string
	Version string
	ID      string // OSV/GHSA id, e.g. GHSA-xxxx or MAL-2024-xxxx
	Summary string
}

// osvBatchURL is OSV's bulk endpoint: one POST covers a whole lockfile.
const osvBatchURL = "https://api.osv.dev/v1/querybatch"

// batchSize stays under OSV's request limits while keeping round-trips low.
const batchSize = 500

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
		var parsed struct {
			Results []struct {
				Vulns []struct {
					ID      string `json:"id"`
					Summary string `json:"summary"`
				} `json:"vulns"`
			} `json:"results"`
		}
		err = json.NewDecoder(resp.Body).Decode(&parsed)
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
