package registry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"depguard/internal/config"
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

// An allowlisted name that is NOT internal still bypasses the filters.
func TestRewriteAllowStillBypasses(t *testing.T) {
	p := &Proxy{cfg: config.Config{Allow: []string{"@acme/*"}, Cooldown: time.Hour}}
	raw := []byte(`{"name":"@acme/ok","versions":{"1.0.0":{}},"dist-tags":{"latest":"1.0.0"}}`)
	out, err := p.rewrite("@acme/ok", raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(raw) {
		t.Errorf("allowlisted packument was rewritten:\n%s", out)
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
