package advisory

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"depguard/internal/lockfile"
)

// TestCheckParsesVulns confirms a normal 200 response maps positionally to the
// queried packages.
func TestCheckParsesVulns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// results[i] answers queries[i]; second package has a hit.
		w.Write([]byte(`{"results":[{},{"vulns":[{"id":"GHSA-xxxx","summary":"bad"}]}]}`))
	}))
	defer srv.Close()
	old := osvBatchURL
	osvBatchURL = srv.URL
	defer func() { osvBatchURL = old }()

	vulns, err := Check([]lockfile.Pkg{
		{Name: "good", Version: "1.0.0"},
		{Name: "evil", Version: "9.9.9"},
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(vulns) != 1 || vulns[0].Package != "evil" || vulns[0].ID != "GHSA-xxxx" {
		t.Fatalf("got %+v, want one hit on evil@9.9.9", vulns)
	}
}

// TestCheckFailsLoudOnNon200 is the #1 fix: the advisory gate must NOT decode a
// rate-limit / outage into an empty "no advisories" result.
func TestCheckFailsLoudOnNon200(t *testing.T) {
	for _, code := range []int{http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusForbidden} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			w.Write([]byte(`{"results":[]}`)) // a parseable body must NOT mask the error
		}))
		old := osvBatchURL
		osvBatchURL = srv.URL
		_, err := Check([]lockfile.Pkg{{Name: "x", Version: "1.0.0"}})
		osvBatchURL = old
		srv.Close()
		if err == nil {
			t.Errorf("status %d: expected an error, got nil (gate would silently green)", code)
		}
	}
}

// TestCheckCapsResponseBody verifies the response is size-limited: with a tiny
// cap, an over-cap body is truncated to invalid JSON and surfaces as an error
// rather than being read unbounded.
func TestCheckCapsResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"results":[` + strings.Repeat(" ", 4096) + `]}`))
	}))
	defer srv.Close()
	oldURL, oldCap := osvBatchURL, maxOSVResponse
	osvBatchURL, maxOSVResponse = srv.URL, 16
	defer func() { osvBatchURL, maxOSVResponse = oldURL, oldCap }()

	if _, err := Check([]lockfile.Pkg{{Name: "x", Version: "1.0.0"}}); err == nil {
		t.Error("expected a decode error from the capped (truncated) body, got nil")
	}
}

// TestParseSeverity covers the label map, case-insensitivity, the medium alias,
// and that anything unrecognized fails closed to SevUnknown with ok=false.
func TestParseSeverity(t *testing.T) {
	cases := []struct {
		in   string
		want Severity
		ok   bool
	}{
		{"LOW", SevLow, true},
		{"low", SevLow, true},
		{"Moderate", SevModerate, true},
		{"medium", SevModerate, true}, // alias
		{"HIGH", SevHigh, true},
		{" critical ", SevCritical, true},
		{"", SevUnknown, false},
		{"bogus", SevUnknown, false},
	}
	for _, c := range cases {
		got, ok := ParseSeverity(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("ParseSeverity(%q) = (%v,%v), want (%v,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

// TestSeverityZeroValueIsUnknown pins the fail-closed invariant: a Vuln nobody
// enriched must read as SevUnknown (the zero value), not as a low severity that
// would slip under a threshold.
func TestSeverityZeroValueIsUnknown(t *testing.T) {
	var v Vuln
	if v.Severity != SevUnknown {
		t.Fatalf("zero-value Severity = %v, want SevUnknown (fail closed)", v.Severity)
	}
}

// TestBlocks covers the gating decision: MAL-* and unknown always block; scored
// hits block at/above the threshold and warn below it.
func TestBlocks(t *testing.T) {
	threshold := SevHigh
	cases := []struct {
		name string
		v    Vuln
		want bool
	}{
		{"mal always blocks even if low", Vuln{ID: "MAL-2024-1", Severity: SevLow}, true},
		{"unknown blocks (fail closed)", Vuln{ID: "GHSA-x", Severity: SevUnknown}, true},
		{"critical blocks", Vuln{ID: "GHSA-x", Severity: SevCritical}, true},
		{"high blocks (at threshold)", Vuln{ID: "GHSA-x", Severity: SevHigh}, true},
		{"moderate warns (below)", Vuln{ID: "GHSA-x", Severity: SevModerate}, false},
		{"low warns (below)", Vuln{ID: "GHSA-x", Severity: SevLow}, false},
	}
	for _, c := range cases {
		if got := c.v.Blocks(threshold); got != c.want {
			t.Errorf("%s: Blocks(high) = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestBlocksThresholdModerate confirms lowering the threshold to moderate flips
// a moderate hit from warn to block.
func TestBlocksThresholdModerate(t *testing.T) {
	v := Vuln{ID: "GHSA-x", Severity: SevModerate}
	if v.Blocks(SevHigh) {
		t.Error("moderate should warn under high threshold")
	}
	if !v.Blocks(SevModerate) {
		t.Error("moderate should block under moderate threshold")
	}
}

// TestSeveritiesReadsDatabaseSpecific verifies the enrichment fetch reads
// database_specific.severity and dedups distinct ids.
func TestSeveritiesReadsDatabaseSpecific(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		id := strings.TrimPrefix(r.URL.Path, "/")
		switch id {
		case "GHSA-high":
			w.Write([]byte(`{"database_specific":{"severity":"HIGH"}}`))
		case "GHSA-mod":
			w.Write([]byte(`{"database_specific":{"severity":"MODERATE"}}`))
		default:
			w.Write([]byte(`{}`)) // no severity -> absent -> SevUnknown for caller
		}
	}))
	defer srv.Close()
	old := osvVulnURL
	osvVulnURL = srv.URL + "/"
	defer func() { osvVulnURL = old }()

	got := Severities([]string{"GHSA-high", "GHSA-mod", "GHSA-high", "GHSA-none"})
	if got["GHSA-high"] != SevHigh {
		t.Errorf("GHSA-high = %v, want high", got["GHSA-high"])
	}
	if got["GHSA-mod"] != SevModerate {
		t.Errorf("GHSA-mod = %v, want moderate", got["GHSA-mod"])
	}
	if _, ok := got["GHSA-none"]; ok {
		t.Error("a record with no severity must be ABSENT (caller reads it as unknown)")
	}
	if hits != 3 {
		t.Errorf("fetched %d times, want 3 (duplicate GHSA-high deduped)", hits)
	}
}

// TestSeveritiesReadsCVSSLabel verifies the CVSS fallback when a feed populates
// severity[].score with a bare label rather than database_specific.
func TestSeveritiesReadsCVSSLabel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"severity":[{"type":"CVSS_V3","score":"critical"}]}`))
	}))
	defer srv.Close()
	old := osvVulnURL
	osvVulnURL = srv.URL + "/"
	defer func() { osvVulnURL = old }()

	got := Severities([]string{"GHSA-c"})
	if got["GHSA-c"] != SevCritical {
		t.Errorf("CVSS label fallback = %v, want critical", got["GHSA-c"])
	}
}

// TestSeveritiesFailOpenOnError confirms a non-200 / network error leaves the id
// ABSENT (caller treats as unknown -> blocks), never decoding to a low severity.
func TestSeveritiesFailOpenOnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	old := osvVulnURL
	osvVulnURL = srv.URL + "/"
	defer func() { osvVulnURL = old }()

	got := Severities([]string{"GHSA-err"})
	if _, ok := got["GHSA-err"]; ok {
		t.Error("a 500 must leave the id absent (caller blocks), not score it")
	}
}

// TestSeveritiesRespectsCap confirms the fetch cap bounds fan-out; ids beyond
// the cap stay absent (and therefore block).
func TestSeveritiesRespectsCap(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Write([]byte(`{"database_specific":{"severity":"LOW"}}`))
	}))
	defer srv.Close()
	old, oldCap := osvVulnURL, maxSeverityFetches
	osvVulnURL = srv.URL + "/"
	maxSeverityFetches = 2
	defer func() { osvVulnURL = old; maxSeverityFetches = oldCap }()

	got := Severities([]string{"a", "b", "c", "d"})
	if hits != 2 {
		t.Errorf("fetched %d, want 2 (capped)", hits)
	}
	if len(got) != 2 {
		t.Errorf("scored %d ids, want 2", len(got))
	}
}

// TestBlockingVersionsTiersBySeverity is the regression for the proxy
// over-block bug: the resolve-time OSV filter must drop only versions whose
// advisory BLOCKS under the threshold (MAL-*, unscored, or >= threshold), NOT
// every version that merely carries an advisory. A moderate-severity advisory
// with a wide affected range (e.g. nodemailer GHSA-268h-hp4c-crq3, <8.0.9) must
// NOT make an aged, otherwise-fine version uninstallable when the threshold is
// the default HIGH — that hit only WARNS at check time (DESIGN.md §12a).
func TestBlockingVersionsTiersBySeverity(t *testing.T) {
	// versions are queried positionally in the slice order below.
	versions := []string{"1.0.0", "2.0.0", "3.0.0", "4.0.0", "5.0.0"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if strings.HasPrefix(r.URL.Path, "/vulns/") {
			switch strings.TrimPrefix(r.URL.Path, "/vulns/") {
			case "GHSA-HIGH":
				w.Write([]byte(`{"database_specific":{"severity":"HIGH"}}`))
			case "GHSA-MOD":
				w.Write([]byte(`{"database_specific":{"severity":"MODERATE"}}`))
			default: // MAL-* and the unknown id carry no scorable severity
				w.Write([]byte(`{}`))
			}
			return
		}
		// querybatch: results[i] answers versions[i].
		w.Write([]byte(`{"results":[` +
			`{"vulns":[{"id":"GHSA-HIGH"}]},` + // 1.0.0 high -> block
			`{"vulns":[{"id":"GHSA-MOD"}]},` + // 2.0.0 moderate -> warn-tier, NOT block
			`{},` + // 3.0.0 clean -> not flagged
			`{"vulns":[{"id":"MAL-2024-1"}]},` + // 4.0.0 malicious -> always block
			`{"vulns":[{"id":"GHSA-UNK"}]}` + // 5.0.0 unscored -> fail closed, block
			`]}`))
	}))
	defer srv.Close()
	ob, ov := osvBatchURL, osvVulnURL
	osvBatchURL, osvVulnURL = srv.URL+"/querybatch", srv.URL+"/vulns/"
	defer func() { osvBatchURL, osvVulnURL = ob, ov }()

	// Default HIGH threshold: moderate does NOT gate; clean is absent.
	got, err := BlockingVersions("pkg", versions, SevHigh)
	if err != nil {
		t.Fatalf("BlockingVersions: %v", err)
	}
	for _, v := range []string{"1.0.0", "4.0.0", "5.0.0"} {
		if _, ok := got[v]; !ok {
			t.Errorf("threshold HIGH: %s should block, missing from %v", v, got)
		}
	}
	for _, v := range []string{"2.0.0", "3.0.0"} {
		if _, ok := got[v]; ok {
			t.Errorf("threshold HIGH: %s must NOT block (moderate/clean), got reason %q", v, got[v])
		}
	}

	// Lowering the threshold to MODERATE pulls the moderate hit into blocking.
	got, err = BlockingVersions("pkg", versions, SevModerate)
	if err != nil {
		t.Fatalf("BlockingVersions (moderate): %v", err)
	}
	if _, ok := got["2.0.0"]; !ok {
		t.Errorf("threshold MODERATE: 2.0.0 should now block, got %v", got)
	}
}
