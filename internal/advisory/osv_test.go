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
