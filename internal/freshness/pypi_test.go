package freshness

import (
	"fmt"
	"net/http"
	"net/http/httptest"
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

func TestPyLess(t *testing.T) {
	cases := []struct {
		a, b string
		less bool
	}{{"1.9", "1.10", true}, {"1.0", "1.0.0", false}, {"1.0.0", "1.0", false}, {"2", "1.99", false}}
	for _, c := range cases {
		if pyLess(c.a, c.b) != c.less {
			t.Errorf("pyLess(%s,%s) != %v", c.a, c.b, c.less)
		}
	}
	for v, want := range map[string]bool{"1.2.3": true, "1.0rc1": false, "1.0.post1": false, "1.0.dev0": false, "1..0": false, "1.0+local": false} {
		if pyStable(v) != want {
			t.Errorf("pyStable(%q) != %v", v, want)
		}
	}
}
