package registry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"depguard/internal/advisory"
	"depguard/internal/config"
	"depguard/internal/provenance"
)

// A name in BOTH allow: and internal-scopes: must still be blocked. The
// dependency-confusion gate outranks the allowlist — a stale `allow:` entry
// must not be able to unlock the public-registry resolution of an internal name.
func TestRewriteInternalOutranksAllow(t *testing.T) {
	p := &Proxy{cfg: config.Config{
		Allow:          []string{"@acme/*"},
		InternalScopes: []string{"@acme/*"},
		Cooldown:       0,
	}}
	raw := []byte(`{"name":"@acme/secret","versions":{"1.0.0":{}},"dist-tags":{"latest":"1.0.0"}}`)
	out, err := p.rewrite("@acme/secret", raw)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if v, _ := doc["versions"].(map[string]any); len(v) != 0 {
		t.Errorf("versions = %v, want empty (internal scope must block despite allow:)", v)
	}
	if d, _ := doc["dist-tags"].(map[string]any); len(d) != 0 {
		t.Errorf("dist-tags = %v, want empty", d)
	}
	if len(p.blocked) == 0 {
		t.Error("expected a blocked record for the dependency-confusion hit")
	}
}

// An allowlisted (non-internal) name skips cooldown + typosquat. On a loopback
// registry the OSV/signature filters don't apply either, so a fresh version
// passes untouched.
func TestRewriteAllowStillBypasses(t *testing.T) {
	p := &Proxy{cfg: config.Config{Allow: []string{"@acme/*"}, Cooldown: time.Hour, Registry: "http://127.0.0.1:1234"}}
	raw := []byte(`{"name":"@acme/ok","versions":{"1.0.0":{}},"dist-tags":{"latest":"1.0.0"}}`)
	out, err := p.rewrite("@acme/ok", raw)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if v, _ := doc["versions"].(map[string]any); len(v) != 1 {
		t.Errorf("versions = %v, want 1.0.0 kept (cooldown skipped for allow)", v)
	}
	if len(p.blocked) != 0 {
		t.Errorf("allowlisted fresh package filtered %d version(s), want 0", len(p.blocked))
	}
}

// `allow:` skips cooldown + typosquat, but must NOT bypass the OSV filter: an
// allowlisted name whose only version is OSV-blocked still gets it dropped.
func TestRewriteAllowStillFiltersOSV(t *testing.T) {
	old := osvBlockingVersions
	osvBlockingVersions = func(string, []string, advisory.Severity) (map[string]string, error) {
		return map[string]string{"1.0.0": "MAL-2024-0001"}, nil
	}
	defer func() { osvBlockingVersions = old }()

	p := &Proxy{cfg: config.Config{Allow: []string{"@acme/*"}, Registry: "https://registry.example"}}
	p.keyring = &provenance.Keyring{} // present but empty; no signatures on the version below anyway
	raw := []byte(`{"name":"@acme/ok","versions":{"1.0.0":{}},"dist-tags":{"latest":"1.0.0"}}`)
	out, err := p.rewrite("@acme/ok", raw)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if v, _ := doc["versions"].(map[string]any); len(v) != 0 {
		t.Errorf("versions = %v, want empty (OSV must still gate an allowed name)", v)
	}
	if len(p.blocked) == 0 || !strings.Contains(p.blocked[0].Reason, "OSV") {
		t.Errorf("blocked = %+v, want an OSV advisory record", p.blocked)
	}
}

// `allow:` must NOT bypass the registry-signature tamper check: an allowlisted
// name with a signature PRESENT but not verifiable is dropped.
func TestRewriteAllowStillFiltersInvalidSignature(t *testing.T) {
	old := osvBlockingVersions
	osvBlockingVersions = func(string, []string, advisory.Severity) (map[string]string, error) { return nil, nil }
	defer func() { osvBlockingVersions = old }()

	p := &Proxy{cfg: config.Config{Allow: []string{"@acme/*"}, Registry: "https://registry.example"}}
	p.keyring = &provenance.Keyring{} // empty keyring → a present signature can't verify → "present but INVALID"
	raw := []byte(`{"name":"@acme/ok","versions":{"1.0.0":{"dist":{"integrity":"sha512-abc","signatures":[{"keyid":"k","sig":"AA=="}]}}},"dist-tags":{"latest":"1.0.0"}}`)
	out, err := p.rewrite("@acme/ok", raw)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if v, _ := doc["versions"].(map[string]any); len(v) != 0 {
		t.Errorf("versions = %v, want empty (invalid signature must gate an allowed name)", v)
	}
	if len(p.blocked) == 0 || !strings.Contains(p.blocked[0].Reason, "signature") {
		t.Errorf("blocked = %+v, want a signature record", p.blocked)
	}
}

// `allow:` DOES skip cooldown: a version published moments ago (well inside the
// cooldown) survives for an allowlisted name — proving the skip is real.
func TestRewriteAllowSkipsCooldown(t *testing.T) {
	old := osvBlockingVersions
	osvBlockingVersions = func(string, []string, advisory.Severity) (map[string]string, error) { return nil, nil }
	defer func() { osvBlockingVersions = old }()

	p := &Proxy{cfg: config.Config{Allow: []string{"@acme/*"}, Cooldown: 30 * 24 * time.Hour, Registry: "https://registry.example"}}
	p.keyring = &provenance.Keyring{}
	now := time.Now().UTC().Format(time.RFC3339)
	raw := []byte(`{"name":"@acme/ok","versions":{"1.0.0":{}},"time":{"1.0.0":"` + now + `"},"dist-tags":{"latest":"1.0.0"}}`)
	out, err := p.rewrite("@acme/ok", raw)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if v, _ := doc["versions"].(map[string]any); len(v) != 1 {
		t.Errorf("versions = %v, want 1.0.0 kept (cooldown must be skipped for allow)", v)
	}
}

// An oversized upstream packument must fail CLOSED (502), not be silently
// clipped into a short document that would filter as if versions never existed.
func TestPackumentSizeCapFailsClosed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"name":"big","versions":{},"pad":"`+strings.Repeat("x", 4096)+`"}`)
	}))
	defer upstream.Close()

	old := maxPackumentBytes
	maxPackumentBytes = 32
	defer func() { maxPackumentBytes = old }()

	p := &Proxy{
		cfg:      config.Config{Registry: upstream.URL},
		client:   upstream.Client(),
		packuCac: map[string][]byte{},
	}
	rec := httptest.NewRecorder()
	p.handle(rec, httptest.NewRequest(http.MethodGet, "/big", nil))
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d (over-cap body must fail closed)", rec.Code, http.StatusBadGateway)
	}
}
