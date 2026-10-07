package freshness

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"depguard/internal/lockfile"
)

func daysAgo(d int) string { return time.Now().UTC().AddDate(0, 0, -d).Format(time.RFC3339) }

// pypiServer serves PyPI's JSON API for one project "pkg".
func pypiServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	// old: earliest file 40d ago (a wheel added 1d ago must not make it young).
	mux.HandleFunc("/pypi/pkg/1.0/json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"urls":[{"upload_time_iso_8601":%q},{"upload_time_iso_8601":%q}]}`, daysAgo(1), daysAgo(40))
	})
	mux.HandleFunc("/pypi/pkg/2.0/json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"urls":[{"upload_time_iso_8601":%q}]}`, daysAgo(2))
	})
	mux.HandleFunc("/pypi/pkg/3.0/json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"urls":[]}`) // yanked-everything / no files: unknown age
	})
	mux.HandleFunc("/pypi/pkg/json", func(w http.ResponseWriter, r *http.Request) {
		f := func(d int) string { return fmt.Sprintf(`[{"upload_time_iso_8601":%q}]`, daysAgo(d)) }
		fmt.Fprintf(w, `{"releases":{"1.9":%s,"1.10":%s,"1.11rc1":%s,"1.12.post1":%s,"2.0":%s,"0.9":[]}}`,
			f(60), f(30), f(30), f(30), f(2))
	})
	return httptest.NewServer(mux)
}

func TestCheckPyPI(t *testing.T) {
	srv := pypiServer(t)
	defer srv.Close()
	pkgs := []lockfile.Pkg{
		{Name: "pkg", Version: "1.0", Ecosystem: "pypi"},
		{Name: "pkg", Version: "2.0", Ecosystem: "pypi"},
		{Name: "pkg", Version: "3.0", Ecosystem: "pypi"},
		{Name: "pkg", Version: "9.9", Ecosystem: "pypi"}, // 404 → warning
	}
	viol, warns := Check(srv.URL, pkgs, 14*24*time.Hour, nil)
	got := map[string]bool{}
	for _, v := range viol {
		got[v.Version] = true
	}
	if len(viol) != 2 || !got["2.0"] || !got["3.0"] {
		t.Errorf("violations = %+v, want 2.0 (fresh) + 3.0 (no timestamp)", viol)
	}
	if len(warns) != 1 {
		t.Errorf("warnings = %v, want one 404", warns)
	}
}

func TestLatestSafePyPI(t *testing.T) {
	srv := pypiServer(t)
	defer srv.Close()
	got, err := LatestSafe(srv.URL, "pypi", "pkg", 14*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// 1.10 > 1.9 numerically; rc/post are not stable; 2.0 is too fresh.
	if got != "1.10" {
		t.Errorf("LatestSafe = %q, want 1.10", got)
	}
}

// jsonServer answers every request with body (status 200) or the given status.
func jsonServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func pypiPkg(v string) []lockfile.Pkg {
	return []lockfile.Pkg{{Name: "pkg", Version: v, Ecosystem: "pypi"}}
}

// A malformed upload time is ignored; the other files still date the release.
func TestPyPIMalformedUploadTimeIgnored(t *testing.T) {
	srv := jsonServer(t, 200, fmt.Sprintf(`{"urls":[{"upload_time_iso_8601":"yesterday-ish"},{"upload_time_iso_8601":%q}]}`, daysAgo(40)))
	if viol, warns := Check(srv.URL, pypiPkg("1.0"), 14*24*time.Hour, nil); len(viol) != 0 || len(warns) != 0 {
		t.Errorf("viol=%v warns=%v, want clean", viol, warns)
	}
	srv = jsonServer(t, 200, `{"urls":[{"upload_time_iso_8601":"garbage"}]}`)
	if viol, _ := Check(srv.URL, pypiPkg("1.0"), time.Hour, nil); len(viol) != 1 || viol[0].Age != 0 {
		t.Errorf("only-malformed times must read as no timestamp (fail closed): %v", viol)
	}
}

// Exactly cooldown old is past it; one second younger is inside it.
func TestPyPICooldownBoundary(t *testing.T) {
	cool := 14 * 24 * time.Hour
	for _, c := range []struct {
		age  time.Duration
		viol bool
	}{{cool, false}, {cool - time.Second, true}} {
		ts := time.Now().Add(-c.age).UTC().Format(time.RFC3339Nano)
		srv := jsonServer(t, 200, fmt.Sprintf(`{"urls":[{"upload_time_iso_8601":%q}]}`, ts))
		if viol, _ := Check(srv.URL, pypiPkg("1.0"), cool, nil); (len(viol) == 1) != c.viol {
			t.Errorf("age %v: violations %v, want violation=%v", c.age, viol, c.viol)
		}
	}
}

// A network failure is a per-package warning naming the package, not a violation.
func TestPyPINetworkErrorWarns(t *testing.T) {
	srv := jsonServer(t, 200, "{}")
	url := srv.URL
	srv.Close()
	viol, warns := Check(url, pypiPkg("1.0"), time.Hour, nil)
	if len(viol) != 0 || len(warns) != 1 || !strings.HasPrefix(warns[0], "pkg@1.0:") {
		t.Errorf("viol=%v warns=%v", viol, warns)
	}
}

func TestLatestSafePyPIEdges(t *testing.T) {
	f := func(d int) string { return fmt.Sprintf(`[{"upload_time_iso_8601":%q}]`, daysAgo(d)) }
	cool := 14 * 24 * time.Hour
	body := fmt.Sprintf(`{"releases":{"1.0":%s,"1.1+cpu":%s,"1.2.dev1":%s,"1.3a1":%s,"1.4":[],"1.5":%s,"0.9":%s}}`,
		f(90), f(60), f(60), f(60), f(30), f(120))
	if got, err := LatestSafe(jsonServer(t, 200, body).URL, "pypi", "pkg", cool); err != nil || got != "1.5" {
		t.Errorf("LatestSafe = %q, %v; want 1.5 (local/dev/pre/empty skipped)", got, err)
	}
	if got, _ := LatestSafe(jsonServer(t, 200, body).URL, "pypi", "pkg", 100*24*time.Hour); got != "0.9" {
		t.Errorf("highest past a 100d cooldown = %q, want 0.9 (not the newest)", got)
	}
	if got, err := LatestSafe(jsonServer(t, 200, fmt.Sprintf(`{"releases":{"1.0":%s}}`, f(1))).URL, "pypi", "pkg", cool); err != nil || got != "" {
		t.Errorf("none qualify: %q, %v", got, err)
	}
	if _, err := LatestSafe(jsonServer(t, 500, "").URL, "pypi", "pkg", cool); err == nil {
		t.Error("500 must error")
	}
	if _, err := LatestSafe(jsonServer(t, 200, "<html>").URL, "pypi", "pkg", cool); err == nil {
		t.Error("garbage must error")
	}
}
