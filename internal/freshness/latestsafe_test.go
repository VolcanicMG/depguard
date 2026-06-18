package freshness

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// packumentServer serves a minimal packument: versions + an RFC3339 time map,
// each version aged by the given number of days.
func packumentServer(t *testing.T, name string, ages map[string]int) *httptest.Server {
	t.Helper()
	now := time.Now().UTC()
	versions := "{"
	times := "{"
	first := true
	for v, days := range ages {
		if !first {
			versions += ","
			times += ","
		}
		first = false
		versions += fmt.Sprintf("%q:{}", v)
		times += fmt.Sprintf("%q:%q", v, now.AddDate(0, 0, -days).Format(time.RFC3339))
	}
	versions += "}"
	times += "}"
	body := fmt.Sprintf(`{"name":%q,"versions":%s,"time":%s}`, name, versions, times)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
}

func TestLatestSafePicksNewestPastCooldown(t *testing.T) {
	// 2.0.0 is too fresh (2d); 2.1.0-beta is a prerelease; 1.1.0 is the newest
	// STABLE version past the 14d cooldown.
	srv := packumentServer(t, "pkg", map[string]int{
		"1.0.0":      40,
		"1.1.0":      30,
		"2.0.0":      2,
		"2.1.0-beta": 40,
	})
	defer srv.Close()

	got, err := LatestSafe(srv.URL, "pkg", 14*24*time.Hour)
	if err != nil {
		t.Fatalf("LatestSafe: %v", err)
	}
	if got != "1.1.0" {
		t.Fatalf("LatestSafe = %q, want 1.1.0 (skip too-fresh 2.0.0 and prerelease beta)", got)
	}
}

func TestLatestSafeNoneQualify(t *testing.T) {
	srv := packumentServer(t, "pkg", map[string]int{"1.0.0": 3, "1.0.1": 1})
	defer srv.Close()
	got, err := LatestSafe(srv.URL, "pkg", 14*24*time.Hour)
	if err != nil {
		t.Fatalf("LatestSafe: %v", err)
	}
	if got != "" {
		t.Fatalf("LatestSafe = %q, want \"\" (every version inside cooldown)", got)
	}
}

func TestLatestSafeRegistryError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()
	if _, err := LatestSafe(srv.URL, "pkg", 14*24*time.Hour); err == nil {
		t.Fatal("LatestSafe should error on a non-200 registry response")
	}
}
