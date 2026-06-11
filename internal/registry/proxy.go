// Package registry implements the ephemeral filtering proxy (DESIGN.md §5).
//
// The trick: depguard doesn't "block" installs — it rewrites what the package
// manager is allowed to SEE. npm asks the proxy for a package's metadata (the
// "packument"); the proxy fetches the real one upstream, deletes versions that
// violate policy (too young, advisory-flagged), repoints `latest` at the
// newest survivor, and hands it back. npm then resolves normally and picks a
// safe version on its own — no error path, no failed build.
//
// The proxy binds 127.0.0.1 on a random port and lives only for the duration
// of one `guard install` command. Nothing persists, nothing listens between
// commands.
package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"depguard/internal/advisory"
	"depguard/internal/config"
	"depguard/internal/provenance"
	"depguard/internal/semver"
	"depguard/internal/typosquat"
)

// Blocked records one version the proxy hid from the package manager,
// so the install summary can tell the human what was filtered and why.
type Blocked struct {
	Package string
	Version string
	Reason  string
}

// Proxy is a single-command npm registry filter.
type Proxy struct {
	cfg        config.Config
	server     *http.Server
	addr       string
	client     *http.Client
	mu         sync.Mutex
	blocked    []Blocked
	deprecated []Blocked         // reuses Blocked: Reason holds the deprecation message
	packuCac   map[string][]byte // per-command packument cache: npm re-asks during resolution

	keyringOnce sync.Once
	keyring     *provenance.Keyring // npm signing keys, fetched at most once per command
}

// keys lazily fetches npm's signing keyring (once per command). Returns nil on
// any failure so the caller fails OPEN — a keys-endpoint blip must not break
// installs; the cooldown/OSV layers still stand.
func (p *Proxy) keys() *provenance.Keyring {
	p.keyringOnce.Do(func() {
		kr, err := provenance.FetchKeyring(p.client, p.cfg.Registry)
		if err == nil {
			p.keyring = kr
		}
	})
	return p.keyring
}

// Start binds the proxy to a random localhost port and begins serving.
// Always pair with Stop (defer p.Stop()).
func Start(cfg config.Config) (*Proxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &Proxy{
		cfg: cfg,
		// Generous timeout: packuments for huge packages (types/node) are MBs.
		client:   &http.Client{Timeout: 60 * time.Second},
		packuCac: map[string][]byte{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", p.handle)
	p.server = &http.Server{Handler: mux}
	p.addr = "http://" + ln.Addr().String()
	go p.server.Serve(ln) //nolint:errcheck // closed via Stop; Serve always returns ErrServerClosed
	return p, nil
}

// URL returns the registry URL to point npm at (--registry=...).
func (p *Proxy) URL() string { return p.addr }

// Stop tears the proxy down. The box is ephemeral by design.
func (p *Proxy) Stop() { p.server.Close() }

// BlockedVersions returns everything the proxy filtered during this command.
func (p *Proxy) BlockedVersions() []Blocked {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Blocked(nil), p.blocked...)
}

// handle routes the two request shapes npm sends a registry:
//   - GET /<name>            → packument (metadata)  → filter + rewrite
//   - GET /<name>/-/<f>.tgz  → tarball               → stream through unmodified
func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.URL.Path, "/-/") {
		p.streamTarball(w, r)
		return
	}
	p.servePackument(w, r)
}

// servePackument fetches the upstream packument, applies the version filters,
// and returns the rewritten document. This function IS the decision engine's
// front half (cooldown + allowlist); the static scan runs post-install where
// the unpacked tree is available.
func (p *Proxy) servePackument(w http.ResponseWriter, r *http.Request) {
	name, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/"))
	if err != nil || name == "" {
		http.Error(w, "bad package path", http.StatusBadRequest)
		return
	}

	p.mu.Lock()
	cached, ok := p.packuCac[name]
	p.mu.Unlock()
	if ok {
		w.Header().Set("Content-Type", "application/json")
		w.Write(cached) //nolint:errcheck
		return
	}

	upstream := p.cfg.Registry + "/" + url.PathEscape(name)
	resp, err := p.client.Get(upstream)
	if err != nil {
		http.Error(w, "upstream fetch failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// 404 etc. pass through untouched so npm reports the real error.
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body) //nolint:errcheck
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "upstream read failed", http.StatusBadGateway)
		return
	}

	out, err := p.rewrite(name, body)
	if err != nil {
		// Fail open on rewrite bugs? No — fail CLOSED. A filter error must
		// not silently expose unfiltered versions.
		http.Error(w, "guard filter error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	p.mu.Lock()
	p.packuCac[name] = out
	p.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Write(out) //nolint:errcheck
}

// rewrite applies the cooldown/allowlist filters to a raw packument and
// repoints dist-tags at surviving versions.
func (p *Proxy) rewrite(name string, raw []byte) ([]byte, error) {
	// Generic map, not structs: packuments carry many fields we must preserve
	// byte-for-byte in spirit (npm reads more than we model).
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("packument parse: %w", err)
	}

	versions, _ := doc["versions"].(map[string]any)
	times, _ := doc["time"].(map[string]any)
	if versions == nil {
		return raw, nil // no versions map (weird doc) — nothing to filter
	}

	// Allowlisted packages (your own scopes) bypass every filter — including
	// the typosquat gate below, which is the escape hatch for a legitimate
	// name that happens to look like a popular one.
	if p.cfg.Allowed(name) {
		return raw, nil
	}

	// Dependency-confusion gate: a name the repo declared INTERNAL must come
	// from a private registry, never the public one this proxy fetches. If it
	// resolves here, that's the confusion attack — block every version.
	if p.cfg.Internal(name) {
		p.block(name, "*", "internal scope resolving from the PUBLIC registry (dependency-confusion guard)")
		doc["versions"] = map[string]any{}
		doc["dist-tags"] = map[string]any{}
		return json.Marshal(doc)
	}

	// Name-level gate, BEFORE version filtering: if the package NAME itself is
	// an impostor (typosquat or homoglyph of a popular package), no version of
	// it is safe to install. Empty the versions + dist-tags so npm resolves to
	// "no matching version" and fails closed; the reason rides the install
	// summary so the human can `allow:` it in .guardrc if it was intentional.
	if reason, bad := typosquat.Suspicion(name); bad {
		p.block(name, "*", reason)
		doc["versions"] = map[string]any{}
		doc["dist-tags"] = map[string]any{}
		return json.Marshal(doc)
	}

	cutoff := time.Now().Add(-p.cfg.Cooldown)
	var survivors []string
	for v := range versions {
		published, ok := parseTime(times, v)
		switch {
		case !ok:
			// No publish timestamp — can't prove age, so fail closed.
			p.block(name, v, "no publish timestamp in registry time map")
			delete(versions, v)
		case published.After(cutoff):
			p.block(name, v, fmt.Sprintf("published %s ago, cooldown is %s",
				humanDays(time.Since(published)), humanDays(p.cfg.Cooldown)))
			delete(versions, v)
		default:
			survivors = append(survivors, v)
		}
	}

	// Known-bad filter — AVOID, not just recover. Drop versions OSV already
	// flags so npm never resolves to a reported-malicious one. Only meaningful
	// against the real public registry (a local/mock registry's versions aren't
	// in OSV's npm namespace), and fail OPEN on lookup errors: an OSV outage
	// must not break every install (the cooldown layer still stands).
	if !isLoopbackHost(hostOf(p.cfg.Registry)) && len(survivors) > 0 {
		if flagged, err := advisory.CheckVersions(name, survivors); err == nil && len(flagged) > 0 {
			kept := survivors[:0]
			for _, v := range survivors {
				if id, bad := flagged[v]; bad {
					p.block(name, v, "OSV advisory "+id)
					delete(versions, v)
				} else {
					kept = append(kept, v)
				}
			}
			survivors = kept
		}
	}

	// Registry signature filter — block a version whose signature is PRESENT
	// but INVALID (a registry/account-compromise tamper signal that the
	// integrity hash can't catch). Unsigned versions pass (most of the
	// ecosystem still is); per-version "unsigned" noise would just train users
	// to ignore the tool. Public-registry only; fail open if keys won't load.
	if !isLoopbackHost(hostOf(p.cfg.Registry)) && len(survivors) > 0 {
		if kr := p.keys(); kr != nil {
			kept := survivors[:0]
			for _, v := range survivors {
				integrity, sigs := distSignatures(versions[v])
				if ok, signed := kr.Verify(name, v, integrity, sigs); signed && !ok {
					p.block(name, v, "registry signature present but INVALID (possible tampering)")
					delete(versions, v)
					continue
				}
				kept = append(kept, v)
			}
			survivors = kept
		}
	}

	// Repoint dist-tags whose target we removed. `latest` gets the newest
	// survivor (npm installs dist-tags.latest by default — this line is what
	// makes "npm install foo" silently resolve to the safe version). Other
	// tags (next, beta...) are dropped when their target is gone.
	tags, _ := doc["dist-tags"].(map[string]any)
	if tags != nil {
		for tag, target := range tags {
			tv, _ := target.(string)
			if _, alive := versions[tv]; alive {
				continue
			}
			if tag == "latest" {
				if newest := semver.MaxStable(survivors); newest != "" {
					tags[tag] = newest
				} else {
					delete(tags, tag)
				}
			} else {
				delete(tags, tag)
			}
		}
	}

	// Deprecation note: if the version npm will install by default
	// (dist-tags.latest) is flagged deprecated upstream, surface it. Not a
	// block — deprecated isn't malicious — but the human should know, and the
	// data is already parsed here so it's free.
	if tags != nil {
		if lv, _ := tags["latest"].(string); lv != "" {
			if vm, ok := versions[lv].(map[string]any); ok {
				if dep, _ := vm["deprecated"].(string); dep != "" {
					p.note(name, lv, dep)
				}
			}
		}
	}

	return json.Marshal(doc)
}

// streamTarball pipes a tarball request through to the upstream registry.
// Bytes pass through unmodified — npm verifies the packument's integrity hash
// itself, which doubles as our tamper check.
func (p *Proxy) streamTarball(w http.ResponseWriter, r *http.Request) {
	resp, err := p.client.Get(p.cfg.Registry + r.URL.Path)
	if err != nil {
		http.Error(w, "upstream tarball fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck
}

// block records one filtered version for the end-of-install summary.
func (p *Proxy) block(name, version, reason string) {
	p.mu.Lock()
	p.blocked = append(p.blocked, Blocked{name, version, reason})
	p.mu.Unlock()
}

// note records a non-blocking advisory (deprecation) for the install summary.
func (p *Proxy) note(name, version, reason string) {
	p.mu.Lock()
	p.deprecated = append(p.deprecated, Blocked{name, version, reason})
	p.mu.Unlock()
}

// DeprecatedVersions returns the deprecated default-resolutions seen this command.
func (p *Proxy) DeprecatedVersions() []Blocked {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Blocked(nil), p.deprecated...)
}

// distSignatures pulls a version's integrity hash and registry signatures out
// of the generic packument map (versions[v].dist.{integrity,signatures}).
func distSignatures(vobj any) (integrity string, sigs []provenance.Signature) {
	vm, ok := vobj.(map[string]any)
	if !ok {
		return
	}
	dist, ok := vm["dist"].(map[string]any)
	if !ok {
		return
	}
	integrity, _ = dist["integrity"].(string)
	arr, ok := dist["signatures"].([]any)
	if !ok {
		return
	}
	for _, e := range arr {
		em, ok := e.(map[string]any)
		if !ok {
			continue
		}
		kid, _ := em["keyid"].(string)
		sig, _ := em["sig"].(string)
		sigs = append(sigs, provenance.Signature{Keyid: kid, Sig: sig})
	}
	return
}

// hostOf extracts the hostname from a URL, "" on parse failure.
func hostOf(rawurl string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// isLoopbackHost reports whether h is a local address — test harnesses and
// local mock registries, never the public npm namespace OSV indexes.
func isLoopbackHost(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }

// humanDays renders a duration in days/hours — "84531h0m0s" helps no one.
func humanDays(d time.Duration) string {
	days := int(d.Hours()) / 24
	if days >= 1 {
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}

// parseTime pulls version v's publish time out of the packument time map.
func parseTime(times map[string]any, v string) (time.Time, bool) {
	if times == nil {
		return time.Time{}, false
	}
	s, ok := times[v].(string)
	if !ok {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
