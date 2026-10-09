package registry

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"depguard/internal/advisory"
	"depguard/internal/config"
	"depguard/internal/provenance"
	"depguard/internal/waivers"
)

// Install-time waivers (DESIGN.md §13): the OSV filter keeps a flagged version
// only when EVERY blocking id for that exact name@version is actively waived,
// and never for MAL-*. The braces case (every version flagged by
// GHSA-vfj7-8cjw-p6xm, pulled in transitively) is the motivating shape.

const ghsa = "GHSA-vfj7-8cjw-p6xm"

// npmWaiverRewrite runs the npm proxy filter over braces 3.0.2 + 3.0.3 (both
// aged past the cooldown) with OSV stubbed to flagged and the given waivers.
// Returns the surviving versions (sorted) and the proxy for its ledger.
func npmWaiverRewrite(t *testing.T, flagged map[string][]string, ignores map[string]waivers.Entry) ([]string, *Proxy) {
	t.Helper()
	stubOSV(t, func(string, string, []string, advisory.Severity) (map[string][]string, error) { return flagged, nil })
	var wf *waivers.File
	if ignores != nil {
		wf = &waivers.File{Schema: 1, Ignores: ignores}
	}
	p := &Proxy{cfg: config.Config{Registry: "https://registry.example", Cooldown: time.Hour}, wf: wf}
	p.keyring = &provenance.Keyring{} // no signatures on these versions → signature filter passes
	old := time.Now().Add(-400 * 24 * time.Hour).UTC().Format(time.RFC3339)
	raw := `{"name":"braces","versions":{"3.0.2":{},"3.0.3":{}},` +
		`"time":{"3.0.2":"` + old + `","3.0.3":"` + old + `"},"dist-tags":{"latest":"3.0.3"}}`
	out, err := p.rewrite("braces", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	vs, _ := doc["versions"].(map[string]any)
	var kept []string
	for v := range vs {
		kept = append(kept, v)
	}
	slices.Sort(kept)
	return kept, p
}

func active(id string) map[string]waivers.Entry {
	return map[string]waivers.Entry{id: {Reason: "DoS only, input is trusted", Expires: "2099-01-01"}}
}

func bothFlagged(ids ...string) map[string][]string {
	return map[string][]string{"3.0.2": ids, "3.0.3": ids}
}

// Fully waived: the waived version survives and is reported as kept — never
// silently. The un-waived sibling is still dropped. Something survives, so no hint.
func TestOSVWaiverFullyCoveredKept(t *testing.T) {
	kept, p := npmWaiverRewrite(t, bothFlagged(ghsa), active(waivers.AdvisoryID("braces", "3.0.3", ghsa)))
	if !reflect.DeepEqual(kept, []string{"3.0.3"}) {
		t.Fatalf("kept = %v, want [3.0.3]", kept)
	}
	w := p.WaivedVersions()
	if len(w) != 1 || w[0].Version != "3.0.3" || w[0].Reason != ghsa+" expires 2099-01-01 — DoS only, input is trusted" {
		t.Errorf("waived = %+v, want braces@3.0.3 with id + expiry + reason", w)
	}
	if b := p.BlockedVersions(); len(b) != 1 || b[0].Version != "3.0.2" {
		t.Errorf("blocked = %+v, want only 3.0.2", b)
	}
	if f := p.AllFlagged(); len(f) != 0 {
		t.Errorf("flagged = %+v, want none (a version survived)", f)
	}
}

// Partial cover (one of two blocking ids waived) keeps the version blocked; the
// hint lists only the id still missing a waiver.
func TestOSVWaiverPartialBlocked(t *testing.T) {
	kept, p := npmWaiverRewrite(t, bothFlagged(ghsa, "GHSA-other"), active(waivers.AdvisoryID("braces", "3.0.3", ghsa)))
	if len(kept) != 0 {
		t.Fatalf("kept = %v, want none (partial waiver must not unblock)", kept)
	}
	if len(p.WaivedVersions()) != 0 {
		t.Errorf("waived = %+v, want none", p.WaivedVersions())
	}
	want := []Waivable{{Package: "braces", Version: "3.0.3", IDs: []string{"GHSA-other"}}}
	if f := p.AllFlagged(); !reflect.DeepEqual(f, want) {
		t.Errorf("flagged = %+v, want %+v", f, want)
	}
}

// An expired waiver does not suppress — fail closed, same as `guard check`.
func TestOSVWaiverExpiredBlocked(t *testing.T) {
	ign := map[string]waivers.Entry{waivers.AdvisoryID("braces", "3.0.3", ghsa): {Expires: "2000-01-01"}}
	kept, p := npmWaiverRewrite(t, bothFlagged(ghsa), ign)
	if len(kept) != 0 || len(p.WaivedVersions()) != 0 {
		t.Errorf("kept = %v waived = %+v, want nothing (expired waiver)", kept, p.WaivedVersions())
	}
}

// MAL-* is never waivable at install time, even with an active waiver, and the
// all-blocked hint must not offer a waiver command for it.
func TestOSVWaiverMALIgnored(t *testing.T) {
	kept, p := npmWaiverRewrite(t, bothFlagged("MAL-2025-1"), map[string]waivers.Entry{
		waivers.AdvisoryID("braces", "3.0.2", "MAL-2025-1"): {},
		waivers.AdvisoryID("braces", "3.0.3", "MAL-2025-1"): {},
	})
	if len(kept) != 0 || len(p.WaivedVersions()) != 0 {
		t.Errorf("kept = %v waived = %+v, want nothing (MAL-* is never waivable)", kept, p.WaivedVersions())
	}
	if f := p.AllFlagged(); len(f) != 0 {
		t.Errorf("flagged = %+v, want no hint for a malicious package", f)
	}
}

// A waiver pinned to a different version has no effect on this one.
func TestOSVWaiverOtherVersionNoEffect(t *testing.T) {
	flagged := map[string][]string{"3.0.3": {ghsa}}
	kept, p := npmWaiverRewrite(t, flagged, active(waivers.AdvisoryID("braces", "3.0.1", ghsa)))
	if !reflect.DeepEqual(kept, []string{"3.0.2"}) || len(p.WaivedVersions()) != 0 {
		t.Errorf("kept = %v waived = %+v, want only the unflagged 3.0.2", kept, p.WaivedVersions())
	}
}

// No .guard-ignores at all: unchanged behavior (every flagged version dropped,
// reason lists all blocking ids), plus the all-blocked hint naming the newest.
func TestOSVNoWaiversUnchangedWithHint(t *testing.T) {
	kept, p := npmWaiverRewrite(t, bothFlagged(ghsa, "GHSA-two"), nil)
	if len(kept) != 0 {
		t.Fatalf("kept = %v, want none", kept)
	}
	for _, b := range p.BlockedVersions() {
		if b.Reason != "OSV advisory "+ghsa+", GHSA-two" {
			t.Errorf("reason = %q, want both ids", b.Reason)
		}
	}
	want := []Waivable{{Package: "braces", Version: "3.0.3", IDs: []string{ghsa, "GHSA-two"}}}
	if f := p.AllFlagged(); !reflect.DeepEqual(f, want) {
		t.Errorf("flagged = %+v, want %+v", f, want)
	}
}

// PyPI applies the same rule through the shared filter: a fully waived version
// is kept and reported; an un-waived one is dropped and drives the hint when
// nothing else survives.
func TestPyPIOSVWaiver(t *testing.T) {
	stubOSV(t, func(string, string, []string, advisory.Severity) (map[string][]string, error) {
		return map[string][]string{"1.0": {"PYSEC-1"}, "1.1": {"PYSEC-1"}}, nil
	})
	page := simplePage("pkg", [][2]string{{"pkg-1.0.tar.gz", ago(40)}, {"pkg-1.1.tar.gz", ago(40)}}, "1.0", "1.1")

	wf := &waivers.File{Ignores: active(waivers.AdvisoryID("pkg", "1.0", "PYSEC-1"))}
	p := &PyPIProxy{cfg: config.Config{PyPI: "https://pypi.example", Cooldown: time.Hour}, wf: wf}
	doc := rewriteDoc(t, p, "pkg", page)
	if got := fileNames(doc); len(got) != 1 || got[0] != "pkg-1.0.tar.gz" {
		t.Errorf("files = %v, want the waived 1.0 only", got)
	}
	if w := p.WaivedVersions(); len(w) != 1 || w[0].Version != "1.0" {
		t.Errorf("waived = %+v", w)
	}

	p = &PyPIProxy{cfg: config.Config{PyPI: "https://pypi.example", Cooldown: time.Hour}}
	doc = rewriteDoc(t, p, "pkg", page)
	want := []Waivable{{Package: "pkg", Version: "1.1", IDs: []string{"PYSEC-1"}}}
	if f := p.AllFlagged(); len(fileNames(doc)) != 0 || !reflect.DeepEqual(f, want) {
		t.Errorf("files = %v flagged = %+v, want none + %+v", fileNames(doc), f, want)
	}
}

// newestPy prefers a plain release and orders numerically, not lexically.
func TestNewestPy(t *testing.T) {
	if got := newestPy([]string{"1.9", "1.10", "2.0rc1"}); got != "1.10" {
		t.Errorf("newestPy = %q, want 1.10", got)
	}
}

// newestNpm: stable first, prerelease-only still yields one, and unparseable
// versions fall back to the lexical max instead of "" (which would drop the hint).
func TestNewestNpm(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want string
	}{
		{[]string{"1.2.0", "1.10.0"}, "1.10.0"},
		{[]string{"2.0.0-beta.1", "2.0.0-rc.1"}, "2.0.0-rc.1"},
		{[]string{"weird", "zzz"}, "zzz"},
		{nil, ""},
	} {
		if got := newestNpm(c.in); got != c.want {
			t.Errorf("newestNpm(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A NEWER version held back by the cooldown (likely the fix) must turn the hint
// into "wait", not "waive the older flagged one".
func TestOSVHintDefersToCooldownFix(t *testing.T) {
	stubOSV(t, func(string, string, []string, advisory.Severity) (map[string][]string, error) {
		return map[string][]string{"3.0.3": {ghsa}}, nil
	})
	p := &Proxy{cfg: config.Config{Registry: "https://registry.example", Cooldown: 14 * 24 * time.Hour}}
	p.keyring = &provenance.Keyring{}
	old := time.Now().Add(-400 * 24 * time.Hour).UTC().Format(time.RFC3339)
	fresh := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	raw := `{"name":"braces","versions":{"3.0.3":{},"3.0.4":{}},` +
		`"time":{"3.0.3":"` + old + `","3.0.4":"` + fresh + `"},"dist-tags":{"latest":"3.0.4"}}`
	if _, err := p.rewrite("braces", []byte(raw)); err != nil {
		t.Fatal(err)
	}
	want := []Waivable{{Package: "braces", Version: "3.0.3", IDs: []string{ghsa}, Cooldown: "3.0.4"}}
	if f := p.AllFlagged(); !reflect.DeepEqual(f, want) {
		t.Errorf("flagged = %+v, want %+v", f, want)
	}
}

// Fail closed: a version OSV flags with an EMPTY id list is blocked, never
// "fully waived" (vacuous truth), and gets no waiver hint (nothing to waive).
func TestOSVEmptyIDsBlocked(t *testing.T) {
	kept, p := npmWaiverRewrite(t, map[string][]string{"3.0.2": {}, "3.0.3": nil}, active("advisory:braces@3.0.3:x"))
	if len(kept) != 0 || len(p.WaivedVersions()) != 0 || len(p.AllFlagged()) != 0 {
		t.Errorf("kept = %v waived = %+v flagged = %+v, want all blocked, no hint", kept, p.WaivedVersions(), p.AllFlagged())
	}
}

// pip refetches a page across invocations: the kept line and the hint must
// appear once per name@version, not once per fetch.
func TestPyPIWaiverRecordsDeduped(t *testing.T) {
	stubOSV(t, func(string, string, []string, advisory.Severity) (map[string][]string, error) {
		return map[string][]string{"1.0": {"PYSEC-1"}, "1.1": {"PYSEC-2"}}, nil
	})
	page := simplePage("pkg", [][2]string{{"pkg-1.0.tar.gz", ago(40)}, {"pkg-1.1.tar.gz", ago(40)}}, "1.0", "1.1")
	wf := &waivers.File{Ignores: active(waivers.AdvisoryID("pkg", "1.0", "PYSEC-1"))}
	p := &PyPIProxy{cfg: config.Config{PyPI: "https://pypi.example", Cooldown: time.Hour}, wf: wf}
	rewriteDoc(t, p, "pkg", page)
	rewriteDoc(t, p, "pkg", page)
	if w := p.WaivedVersions(); len(w) != 1 {
		t.Errorf("waived = %+v, want one record", w)
	}

	p = &PyPIProxy{cfg: config.Config{PyPI: "https://pypi.example", Cooldown: time.Hour}}
	rewriteDoc(t, p, "pkg", page)
	rewriteDoc(t, p, "pkg", page)
	if f := p.AllFlagged(); len(f) != 1 {
		t.Errorf("flagged = %+v, want one hint", f)
	}
}

// A scoped name's waiver matches through the real request path: npm asks for
// /@scope%2fpkg, servePackument unescapes it, and the waiver ID carries the
// full "@scope/pkg" name.
func TestOSVWaiverScopedThroughServePackument(t *testing.T) {
	stubOSV(t, func(_, name string, _ []string, _ advisory.Severity) (map[string][]string, error) {
		if name != "@scope/pkg" {
			t.Errorf("OSV asked for %q, want @scope/pkg", name)
		}
		return map[string][]string{"1.0.0": {ghsa}}, nil
	})
	old := time.Now().Add(-400 * 24 * time.Hour).UTC().Format(time.RFC3339)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"name":"@scope/pkg","versions":{"1.0.0":{}},"time":{"1.0.0":"` + old + `"},"dist-tags":{"latest":"1.0.0"}}`))
	}))
	defer upstream.Close()
	// Non-loopback registry host (so OSV runs), dialed to the test server.
	tr := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
	}}
	p := &Proxy{
		cfg:      config.Config{Registry: "http://registry.example", Cooldown: time.Hour},
		wf:       &waivers.File{Ignores: active(waivers.AdvisoryID("@scope/pkg", "1.0.0", ghsa))},
		client:   &http.Client{Transport: tr},
		packuCac: map[string][]byte{},
	}
	p.keyring = &provenance.Keyring{}
	rec := httptest.NewRecorder()
	p.handle(rec, httptest.NewRequest(http.MethodGet, "/@scope%2fpkg", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"1.0.0"`) {
		t.Fatalf("status %d body %s, want 1.0.0 kept", rec.Code, rec.Body.String())
	}
	if w := p.WaivedVersions(); len(w) != 1 || w[0].Package != "@scope/pkg" {
		t.Errorf("waived = %+v, want @scope/pkg@1.0.0", w)
	}
}
