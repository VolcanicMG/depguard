// Package maintainer detects publisher changes between a package's versions —
// the fingerprint of an account-takeover supply-chain attack (DESIGN.md §6).
//
// The biggest npm compromises (event-stream, ua-parser-js, node-ipc,
// eslint-scope, coa/rc) were NOT new packages: they were existing, trusted
// packages whose maintainer account was taken over, then republished with a
// malicious version. Cooldown catches that only if it's caught-and-yanked in
// the window; OSV catches it only once reported. Neither looks at WHO
// published. This does: for an installed version, it compares the publisher to
// the publisher of the immediately preceding version, and flags a change (and
// long-dormancy republishes, the other takeover tell).
package maintainer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"depguard/internal/lockfile"
)

// Change is one publisher transition landing on an installed version.
type Change struct {
	Name     string
	Version  string
	PrevUser string // publisher of the preceding version ("" if unknown)
	NewUser  string // publisher of this version
	// GapDays is the dormancy before this version (days since the previous
	// publish); a large gap on top of a publisher change is a stronger signal.
	GapDays int
}

// dormantDays is the gap that makes a republish noteworthy on its own.
const dormantDays = 365

const workers = 8

// Check fetches each package's packument and reports publisher changes that
// land on an installed version. Network errors per package are returned as
// warnings (fail-open: a registry blip must not block a commit). skip exempts
// allowlisted names.
func Check(registry string, pkgs []lockfile.Pkg, skip func(string) bool) ([]Change, []string) {
	// Group installed versions by package name — one packument fetch per name.
	byName := map[string][]string{}
	for _, p := range pkgs {
		if skip != nil && skip(p.Name) {
			continue
		}
		byName[p.Name] = append(byName[p.Name], p.Version)
	}

	type job struct {
		name     string
		versions []string
	}
	jobs := make(chan job)
	var mu sync.Mutex
	var changes []Change
	var warnings []string
	client := &http.Client{Timeout: 30 * time.Second}

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				ch, err := changesFor(client, registry, j.name, j.versions)
				mu.Lock()
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("%s: %v", j.name, err))
				} else {
					changes = append(changes, ch...)
				}
				mu.Unlock()
			}
		}()
	}
	for name, versions := range byName {
		jobs <- job{name, versions}
	}
	close(jobs)
	wg.Wait()
	sort.Slice(changes, func(i, j int) bool {
		return changes[i].Name+changes[i].Version < changes[j].Name+changes[j].Version
	})
	return changes, warnings
}

// changesFor fetches one packument and computes the publisher transitions that
// land on the given installed versions.
func changesFor(client *http.Client, registry, name string, installed []string) ([]Change, error) {
	resp, err := client.Get(registry + "/" + url.PathEscape(name))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned %d", resp.StatusCode)
	}
	// Decode only the fields we need; the rest of the (often MB) packument is
	// skipped by the streaming decoder.
	var doc struct {
		Time     map[string]string `json:"time"`
		Versions map[string]struct {
			NpmUser struct {
				Name string `json:"name"`
			} `json:"_npmUser"`
		} `json:"versions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("packument parse: %w", err)
	}

	// Order all real versions by publish time.
	type pv struct {
		ver  string
		when time.Time
		user string
	}
	var ordered []pv
	for v, vd := range doc.Versions {
		t, _ := time.Parse(time.RFC3339, doc.Time[v])
		ordered = append(ordered, pv{v, t, vd.NpmUser.Name})
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].when.Before(ordered[j].when) })

	pos := map[string]int{}
	for i, p := range ordered {
		pos[p.ver] = i
	}

	var out []Change
	for _, v := range installed {
		i, ok := pos[v]
		if !ok || i == 0 {
			continue // unknown, or the very first version (no predecessor)
		}
		cur, prev := ordered[i], ordered[i-1]
		gap := 0
		if !cur.when.IsZero() && !prev.when.IsZero() {
			gap = int(cur.when.Sub(prev.when).Hours() / 24)
		}
		changed := cur.user != "" && prev.user != "" && cur.user != prev.user
		if changed || gap >= dormantDays {
			out = append(out, Change{
				Name:     name,
				Version:  v,
				PrevUser: prev.user,
				NewUser:  cur.user,
				GapDays:  gap,
			})
		}
	}
	return out, nil
}
