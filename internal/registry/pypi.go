package registry

// The PyPI half of the ephemeral proxy (DESIGN.md §5): a PEP 691 JSON Simple
// index that pip is pointed at with --index-url. Same trick as the npm proxy —
// it rewrites what pip may SEE (files + versions), so pip resolves to a safe
// version on its own. File URLs stay absolute (files.pythonhosted.org): pip
// downloads artifacts directly and verifies each against the page's sha256, so
// the proxy never streams a wheel or sdist.

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"depguard/internal/config"
	"depguard/internal/pyver"
	"depguard/internal/typosquat"
)

// pypiJSON is the PEP 691 media type — the only one this proxy speaks.
const pypiJSON = "application/vnd.pypi.simple.v1+json"

// PyPIProxy is a single-command PyPI Simple-index filter.
type PyPIProxy struct {
	cfg     config.Config
	server  *http.Server
	addr    string
	client  *http.Client
	mu      sync.Mutex
	blocked []Blocked
}

// StartPyPI binds the PyPI proxy to a random localhost port. Always pair with Stop.
func StartPyPI(cfg config.Config) (*PyPIProxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &PyPIProxy{cfg: cfg, client: &http.Client{Timeout: 60 * time.Second}}
	p.server = &http.Server{Handler: http.HandlerFunc(p.handle)}
	p.addr = "http://" + ln.Addr().String()
	go p.server.Serve(ln) //nolint:errcheck // closed via Stop
	return p, nil
}

// URL is the index URL to hand pip (--index-url=...).
func (p *PyPIProxy) URL() string { return p.addr + "/simple/" }

// Stop tears the proxy down.
func (p *PyPIProxy) Stop() { p.server.Close() }

// BlockedVersions returns everything the proxy filtered during this command.
func (p *PyPIProxy) BlockedVersions() []Blocked {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Blocked(nil), p.blocked...)
}

func (p *PyPIProxy) block(name, version, reason string) {
	p.mu.Lock()
	p.blocked = append(p.blocked, Blocked{name, version, reason})
	p.mu.Unlock()
}

// handle serves GET /simple/<name>/ only; everything else is 404.
func (p *PyPIProxy) handle(w http.ResponseWriter, r *http.Request) {
	rest, ok := strings.CutPrefix(r.URL.Path, "/simple/")
	if !ok || rest == "" || r.Method != http.MethodGet || strings.Contains(strings.TrimSuffix(rest, "/"), "/") {
		http.NotFound(w, r)
		return
	}
	if !strings.HasSuffix(rest, "/") {
		http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
		return
	}
	// JSON only, by design: one parser to keep correct (pip >= 22.3, uv, poetry).
	if !strings.Contains(r.Header.Get("Accept"), pypiJSON) {
		http.Error(w, "depguard's PyPI proxy serves "+pypiJSON+" only (PEP 691); upgrade pip to >= 22.3", http.StatusNotAcceptable)
		return
	}
	name := pyver.NormalizeName(strings.TrimSuffix(rest, "/"))

	req, err := http.NewRequest(http.MethodGet, p.cfg.PyPI+"/simple/"+name+"/", nil)
	if err != nil {
		http.Error(w, "guard: bad upstream URL", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Accept", pypiJSON)
	resp, err := p.client.Do(req)
	if err != nil {
		http.Error(w, "guard: upstream fetch failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		http.NotFound(w, r) // no such project — pip reports it
		return
	}
	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("guard: upstream returned %d", resp.StatusCode), http.StatusInternalServerError)
		return
	}
	// cap+1 so an oversized page is DETECTED, not clipped into a shorter one.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPackumentBytes+1))
	if err != nil || int64(len(body)) > maxPackumentBytes {
		http.Error(w, "guard: upstream page unreadable or over the size cap", http.StatusInternalServerError)
		return
	}
	out, err := p.rewrite(name, body)
	if err != nil {
		// Fail CLOSED: a filter error must never expose the unfiltered page.
		http.Error(w, "guard filter error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", pypiJSON)
	w.Write(out) //nolint:errcheck
}

// rewrite filters a PEP 691 project page: name gate → cooldown → OSV, mirroring
// Proxy.rewrite. Every other field (meta, hashes, requires-python, yanked,
// core-metadata, ...) is carried through untouched via the generic map.
// Dependency confusion (internal-scopes) is npm-scope-shaped and not applied.
func (p *PyPIProxy) rewrite(name string, raw []byte) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("simple page parse: %w", err)
	}
	files, ok := doc["files"].([]any)
	if !ok {
		return nil, fmt.Errorf("simple page has no files list")
	}
	// `allow:` skips the cooldown and the name gate, as for npm — it is the only
	// escape from a fail-closed name false positive. Never OSV.
	allowed := p.cfg.Allowed(name)

	if reason, bad := typosquat.SuspicionPyPI(name); bad && !allowed {
		p.block(name, "*", reason)
		doc["files"], doc["versions"] = []any{}, []any{}
		return json.Marshal(doc)
	}

	// Group files by the version their filename names; unparseable → dropped.
	byVer := map[string][]map[string]any{}
	var order []string
	for _, f := range files {
		fm, _ := f.(map[string]any)
		fn, _ := fm["filename"].(string)
		v, ok := pyver.FileVersion(fn)
		if fm == nil || !ok {
			if fn == "" {
				fn = "(missing filename)"
			}
			p.block(name, fn, "unparseable filename")
			continue
		}
		if _, seen := byVer[v]; !seen {
			order = append(order, v)
		}
		byVer[v] = append(byVer[v], fm)
	}

	drop := map[string]bool{}
	var survivors []string
	cutoff := time.Now().Add(-p.cfg.Cooldown)
	for _, v := range order {
		if allowed {
			survivors = append(survivors, v)
			continue
		}
		pub := earliestUploadTime(byVer[v])
		switch {
		case pub.IsZero():
			p.block(name, v, "no upload time (can't prove age)")
			drop[v] = true
		case pub.After(cutoff):
			p.block(name, v, fmt.Sprintf("published %s ago, cooldown is %s",
				humanDays(time.Since(pub)), humanDays(p.cfg.Cooldown)))
			drop[v] = true
		default:
			survivors = append(survivors, v)
		}
	}

	// Known-bad drop, allowed names included; fails OPEN on lookup errors and is
	// skipped for a loopback upstream (mock versions aren't in OSV's namespace).
	if !isLoopbackHost(hostOf(p.cfg.PyPI)) && len(survivors) > 0 {
		if flagged, err := osvBlockingVersions("pypi", name, survivors, p.cfg.AdvisoryThreshold); err == nil {
			for _, v := range survivors {
				if id, bad := flagged[v]; bad {
					p.block(name, v, "OSV advisory "+id)
					drop[v] = true
				}
			}
		}
	}

	kept := []any{}
	for _, v := range order {
		if drop[v] {
			continue
		}
		for _, fm := range byVer[v] {
			kept = append(kept, fm)
		}
	}
	doc["files"] = kept
	if vs, ok := doc["versions"].([]any); ok {
		out := []any{}
		for _, x := range vs {
			// Wheel filenames spell a version's '-' as '_' and may differ in case.
			// A listed version with no files at all is left alone: nothing to fetch.
			if s, _ := x.(string); !drop[strings.ReplaceAll(strings.ToLower(s), "-", "_")] {
				out = append(out, x)
			}
		}
		doc["versions"] = out
	}
	return json.Marshal(doc)
}

// earliestUploadTime is a version's publish time: its FIRST file's PEP 700
// upload-time, so a wheel added later can't make an old release look young and
// vice versa. Zero when no file carries a parseable time.
func earliestUploadTime(files []map[string]any) time.Time {
	var first time.Time
	for _, f := range files {
		s, _ := f["upload-time"].(string)
		t, err := time.Parse(time.RFC3339, s)
		if err == nil && (first.IsZero() || t.Before(first)) {
			first = t
		}
	}
	return first
}
