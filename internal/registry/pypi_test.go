package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"depguard/internal/advisory"
	"depguard/internal/config"
)

func ago(d int) string {
	return time.Now().UTC().AddDate(0, 0, -d).Format("2006-01-02T15:04:05.000000Z")
}

// simplePage builds a PEP 691 page; each file is {filename, upload-time ("" = omit)}.
func simplePage(name string, files [][2]string, versions ...string) string {
	var fs []string
	for _, f := range files {
		up := ""
		if f[1] != "" {
			up = fmt.Sprintf(`,"upload-time":%q`, f[1])
		}
		fs = append(fs, fmt.Sprintf(`{"filename":%q,"url":"https://files.example/%s","hashes":{"sha256":"aa"},"requires-python":">=3.8"%s}`, f[0], f[0], up))
	}
	vb, _ := json.Marshal(versions)
	return fmt.Sprintf(`{"meta":{"api-version":"1.1"},"name":%q,"files":[%s],"versions":%s}`, name, strings.Join(fs, ","), vb)
}

// fetchPage runs one request through a live PyPIProxy over an httptest upstream.
func fetchPage(t *testing.T, cfg config.Config, upstream http.HandlerFunc, path, accept string) (*PyPIProxy, int, map[string]any, string) {
	t.Helper()
	srv := httptest.NewServer(upstream)
	t.Cleanup(srv.Close)
	cfg.PyPI = srv.URL
	if cfg.Cooldown == 0 {
		cfg.Cooldown = 14 * 24 * time.Hour
	}
	p, err := StartPyPI(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Stop)
	req, _ := http.NewRequest(http.MethodGet, strings.TrimSuffix(p.URL(), "/simple/")+path, nil)
	req.Header.Set("Accept", accept)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var doc map[string]any
	_ = json.Unmarshal(body, &doc)
	return p, resp.StatusCode, doc, string(body)
}

func serve(page string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != pypiJSON {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, page)
	}
}

func fileNames(doc map[string]any) []string {
	var out []string
	files, _ := doc["files"].([]any)
	for _, f := range files {
		out = append(out, f.(map[string]any)["filename"].(string))
	}
	return out
}

// Cooldown drops every file of a young version and its versions entry; a
// version's age is its EARLIEST file, so a late wheel doesn't make 1.0 young.
// Missing upload-time and unparseable filenames are dropped too (fail closed).
func TestPyPIProxyCooldown(t *testing.T) {
	page := simplePage("mixed-pkg", [][2]string{
		{"mixed_pkg-1.0.tar.gz", ago(40)},
		{"mixed_pkg-1.0-py3-none-any.whl", ago(1)},
		{"mixed_pkg-2.0-py3-none-any.whl", ago(2)},
		{"mixed_pkg-3.0.tar.gz", ""},
		{"mixed_pkg-weird.egg", ago(40)},
	}, "1.0", "2.0", "3.0")
	p, code, doc, body := fetchPage(t, config.Config{}, serve(page), "/simple/Mixed_Pkg/", pypiJSON)
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	if got := fileNames(doc); len(got) != 2 || got[0] != "mixed_pkg-1.0.tar.gz" || got[1] != "mixed_pkg-1.0-py3-none-any.whl" {
		t.Errorf("files = %v, want both 1.0 files only", got)
	}
	if vs, _ := doc["versions"].([]any); len(vs) != 1 || vs[0] != "1.0" {
		t.Errorf("versions = %v, want [1.0]", vs)
	}
	f0, _ := doc["files"].([]any)[0].(map[string]any)
	if doc["meta"] == nil || f0["requires-python"] != ">=3.8" || f0["hashes"] == nil {
		t.Errorf("fields not carried through: %s", body)
	}
	reasons := map[string]string{}
	for _, b := range p.BlockedVersions() {
		reasons[b.Version] = b.Reason
	}
	if !strings.Contains(reasons["2.0"], "cooldown") || !strings.Contains(reasons["3.0"], "no upload time") ||
		reasons["mixed_pkg-weird.egg"] != "unparseable filename" || len(reasons) != 3 {
		t.Errorf("blocked = %v", reasons)
	}
}

// allow: bypasses the cooldown.
func TestPyPIProxyAllowSkipsCooldown(t *testing.T) {
	page := simplePage("ours", [][2]string{{"ours-2.0-py3-none-any.whl", ago(1)}}, "2.0")
	p, _, doc, _ := fetchPage(t, config.Config{Allow: []string{"ours"}}, serve(page), "/simple/ours/", pypiJSON)
	if len(fileNames(doc)) != 1 || len(p.BlockedVersions()) != 0 {
		t.Errorf("allowlisted fresh version filtered: %v %v", fileNames(doc), p.BlockedVersions())
	}
}

// A typosquat name gets an empty page + a Blocked record.
func TestPyPIProxyNameGate(t *testing.T) {
	page := simplePage("reqeusts", [][2]string{{"reqeusts-1.0-py3-none-any.whl", ago(400)}}, "1.0")
	p, code, doc, _ := fetchPage(t, config.Config{}, serve(page), "/simple/reqeusts/", pypiJSON)
	if code != 200 || len(fileNames(doc)) != 0 {
		t.Fatalf("code=%d files=%v, want empty page", code, fileNames(doc))
	}
	if vs, _ := doc["versions"].([]any); len(vs) != 0 {
		t.Errorf("versions = %v", vs)
	}
	if b := p.BlockedVersions(); len(b) != 1 || b[0].Version != "*" || !strings.Contains(b[0].Reason, "typosquat") {
		t.Errorf("blocked = %+v", b)
	}
}

// JSON-only, redirect for a missing slash, 404 off-route, fail closed upstream.
func TestPyPIProxyProtocolEdges(t *testing.T) {
	page := simplePage("pkg", nil)
	if _, code, _, _ := fetchPage(t, config.Config{}, serve(page), "/simple/pkg/", "text/html"); code != http.StatusNotAcceptable {
		t.Errorf("HTML Accept: %d, want 406", code)
	}
	if _, code, _, _ := fetchPage(t, config.Config{}, serve(page), "/simple/pkg", pypiJSON); code != http.StatusMovedPermanently {
		t.Errorf("no slash: %d, want 301", code)
	}
	if _, code, _, _ := fetchPage(t, config.Config{}, serve(page), "/packages/x.whl", pypiJSON); code != http.StatusNotFound {
		t.Errorf("off-route: %d, want 404", code)
	}
	fail := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }
	if _, code, _, _ := fetchPage(t, config.Config{}, fail, "/simple/pkg/", pypiJSON); code != 500 {
		t.Errorf("upstream 500: %d, want 500", code)
	}
	garbage := func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "<html>nope") }
	if _, code, _, body := fetchPage(t, config.Config{}, garbage, "/simple/pkg/", pypiJSON); code != 500 || strings.Contains(body, "nope") {
		t.Errorf("garbage upstream: %d %q, want 500 without pass-through", code, body)
	}
	missing := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }
	if _, code, _, _ := fetchPage(t, config.Config{}, missing, "/simple/pkg/", pypiJSON); code != 404 {
		t.Errorf("upstream 404: %d, want 404", code)
	}
}

// OSV-blocked versions are dropped for a non-loopback upstream, in the PyPI namespace.
func TestPyPIProxyOSV(t *testing.T) {
	old := osvBlockingVersions
	var gotEco string
	osvBlockingVersions = func(eco, name string, vs []string, _ advisory.Severity) (map[string]string, error) {
		gotEco = eco
		return map[string]string{"1.0": "PYSEC-1"}, nil
	}
	defer func() { osvBlockingVersions = old }()
	p := &PyPIProxy{cfg: config.Config{PyPI: "https://pypi.example", Cooldown: time.Hour}}
	raw := simplePage("pkg", [][2]string{{"pkg-1.0.tar.gz", ago(40)}, {"pkg-1.1.tar.gz", ago(40)}}, "1.0", "1.1")
	out, err := p.rewrite("pkg", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	json.Unmarshal(out, &doc) //nolint:errcheck
	if got := fileNames(doc); len(got) != 1 || got[0] != "pkg-1.1.tar.gz" || gotEco != "pypi" {
		t.Errorf("files=%v eco=%q", got, gotEco)
	}
	if b := p.BlockedVersions(); len(b) != 1 || b[0].Reason != "OSV advisory PYSEC-1" {
		t.Errorf("blocked = %+v", b)
	}
}

func TestPyFileVersion(t *testing.T) {
	cases := map[string]string{
		"requests-2.31.0-py3-none-any.whl":                  "2.31.0",
		"numpy-1.26.4-1-cp312-cp312-manylinux_2_17_x86.whl": "1.26.4", // build tag
		"torch-2.1.0+cpu-cp311-cp311-linux_x86_64.whl":      "2.1.0+cpu",
		"my_pkg-1.0.post1.tar.gz":                           "1.0.post1",
		"my-dashed-pkg-0.3.zip":                             "0.3",
		"Pkg-1.0RC1.tar.bz2":                                "1.0rc1",
	}
	for fn, want := range cases {
		if got, ok := pyFileVersion(fn); !ok || got != want {
			t.Errorf("pyFileVersion(%q) = %q,%v want %q", fn, got, ok, want)
		}
	}
	for _, bad := range []string{"pkg.egg", "pkg-1.0.exe", "pkg.tar.gz", "pkg-.zip", "a-b-c.whl", "x-1.0.tar.xz"} {
		if _, ok := pyFileVersion(bad); ok {
			t.Errorf("pyFileVersion(%q) parsed, want fail", bad)
		}
	}
}

// loopCfg is a config whose PyPI base is loopback, so rewrite() skips OSV.
func loopCfg() config.Config {
	return config.Config{PyPI: "http://127.0.0.1:1", Cooldown: 14 * 24 * time.Hour}
}

func rewriteDoc(t *testing.T, p *PyPIProxy, name, raw string) map[string]any {
	t.Helper()
	out, err := p.rewrite(name, []byte(raw))
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func versionsOf(doc map[string]any) []any { v, _ := doc["versions"].([]any); return v }

func reasons(p *PyPIProxy) map[string]string {
	out := map[string]string{}
	for _, b := range p.BlockedVersions() {
		out[b.Version] = b.Reason
	}
	return out
}

func stubOSV(t *testing.T, fn func(eco, name string, vs []string, _ advisory.Severity) (map[string]string, error)) {
	t.Helper()
	old := osvBlockingVersions
	osvBlockingVersions = fn
	t.Cleanup(func() { osvBlockingVersions = old })
}

// An OSV lookup error fails OPEN: nothing dropped, nothing recorded.
func TestPyPIProxyOSVErrorFailsOpen(t *testing.T) {
	stubOSV(t, func(string, string, []string, advisory.Severity) (map[string]string, error) {
		return nil, fmt.Errorf("osv down")
	})
	p := &PyPIProxy{cfg: config.Config{PyPI: "https://pypi.example", Cooldown: time.Hour}}
	doc := rewriteDoc(t, p, "pkg", simplePage("pkg", [][2]string{{"pkg-1.0.tar.gz", ago(40)}}, "1.0"))
	if len(fileNames(doc)) != 1 || len(p.BlockedVersions()) != 0 {
		t.Errorf("files=%v blocked=%v", fileNames(doc), p.BlockedVersions())
	}
}

// OSV and the cooldown each drop their own version, with distinct reasons.
func TestPyPIProxyOSVAndCooldownTogether(t *testing.T) {
	stubOSV(t, func(_, _ string, vs []string, _ advisory.Severity) (map[string]string, error) {
		return map[string]string{"1.0": "MAL-1"}, nil
	})
	p := &PyPIProxy{cfg: config.Config{PyPI: "https://pypi.example", Cooldown: 14 * 24 * time.Hour}}
	doc := rewriteDoc(t, p, "pkg", simplePage("pkg", [][2]string{
		{"pkg-1.0.tar.gz", ago(40)}, {"pkg-1.1.tar.gz", ago(40)}, {"pkg-2.0.tar.gz", ago(1)},
	}, "1.0", "1.1", "2.0"))
	r := reasons(p)
	if got := fileNames(doc); len(got) != 1 || got[0] != "pkg-1.1.tar.gz" || len(versionsOf(doc)) != 1 {
		t.Errorf("files=%v versions=%v", got, versionsOf(doc))
	}
	if r["1.0"] != "OSV advisory MAL-1" || !strings.Contains(r["2.0"], "cooldown") {
		t.Errorf("reasons = %v", r)
	}
}

func TestPyPIProxyCooldownBoundary(t *testing.T) {
	cool := 14 * 24 * time.Hour
	at := func(d time.Duration) string { return time.Now().Add(-d).UTC().Format(time.RFC3339Nano) }
	for _, c := range []struct {
		age      time.Duration
		cooldown time.Duration
		kept     bool
	}{{cool, cool, true}, {cool - time.Second, cool, false}, {time.Minute, 0, true}} {
		cfg := loopCfg()
		cfg.Cooldown = c.cooldown
		p := &PyPIProxy{cfg: cfg}
		doc := rewriteDoc(t, p, "pkg", simplePage("pkg", [][2]string{{"pkg-1.0.tar.gz", at(c.age)}}, "1.0"))
		if (len(fileNames(doc)) == 1) != c.kept {
			t.Errorf("age %v cooldown %v: files %v, want kept=%v", c.age, c.cooldown, fileNames(doc), c.kept)
		}
	}
}

// versions entries match dropped versions case- and '-'/'_'-insensitively; a
// listed version with no files is left alone.
func TestPyPIProxyVersionsListMatching(t *testing.T) {
	p := &PyPIProxy{cfg: loopCfg()}
	doc := rewriteDoc(t, p, "pkg", simplePage("pkg", [][2]string{
		{"pkg-1.0RC1.tar.gz", ago(1)}, {"pkg-1.0_1-py3-none-any.whl", ago(1)}, {"pkg-0.9.tar.gz", ago(40)},
	}, "0.5", "0.9", "1.0RC1", "1.0-1"))
	want := []any{"0.5", "0.9"}
	if got := versionsOf(doc); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("versions = %v, want %v", got, want)
	}
}

// Malformed file entries are dropped and recorded; a non-array files list fails.
func TestPyPIProxyMalformedFiles(t *testing.T) {
	p := &PyPIProxy{cfg: loopCfg()}
	doc := rewriteDoc(t, p, "pkg", `{"meta":{},"name":"pkg","files":[{"url":"x"},"notamap",{"filename":"pkg-1.0.tar.gz","upload-time":"`+ago(40)+`"}]}`)
	if len(fileNames(doc)) != 1 || reasons(p)["(missing filename)"] != "unparseable filename" || len(p.BlockedVersions()) != 2 {
		t.Errorf("files=%v blocked=%v", fileNames(doc), p.BlockedVersions())
	}
	if _, err := p.rewrite("pkg", []byte(`{"files":{"a":1}}`)); err == nil {
		t.Error("files as an object must fail closed")
	}
}

// upload-time with fractional seconds and with a +00:00 offset both parse.
func TestPyPIProxyUploadTimeFormats(t *testing.T) {
	old := time.Now().Add(-40 * 24 * time.Hour).UTC()
	for _, ts := range []string{old.Format("2006-01-02T15:04:05.123456Z"), old.Format("2006-01-02T15:04:05+00:00")} {
		p := &PyPIProxy{cfg: loopCfg()}
		if doc := rewriteDoc(t, p, "pkg", simplePage("pkg", [][2]string{{"pkg-1.0.tar.gz", ts}})); len(fileNames(doc)) != 1 {
			t.Errorf("%s not parsed: %v", ts, p.BlockedVersions())
		}
	}
}

// Fields the proxy doesn't model survive the round trip unchanged.
func TestPyPIProxyCarriesFields(t *testing.T) {
	raw := `{"meta":{"api-version":"1.1","_last-serial":42},"name":"pkg","project-status":{"status":"active"},` +
		`"files":[{"filename":"pkg-1.0-py3-none-any.whl","url":"https://f/pkg.whl","hashes":{"sha256":"aa","blake2b_256":"bb"},` +
		`"requires-python":">=3.8","yanked":"broken build","core-metadata":{"sha256":"cc"},"dist-info-metadata":true,` +
		`"size":123456,"upload-time":"` + ago(40) + `"}],"versions":["1.0"]}`
	var in map[string]any
	json.Unmarshal([]byte(raw), &in) //nolint:errcheck
	out := rewriteDoc(t, &PyPIProxy{cfg: loopCfg()}, "pkg", raw)
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round trip changed the page:\n in=%v\nout=%v", in, out)
	}
}

func TestPyPIProxyAllowWinsOverNameGate(t *testing.T) {
	cfg := loopCfg()
	cfg.Allow = []string{"reqeusts"}
	p := &PyPIProxy{cfg: cfg}
	doc := rewriteDoc(t, p, "reqeusts", simplePage("reqeusts", [][2]string{{"reqeusts-1.0.tar.gz", ago(1)}}, "1.0"))
	if len(fileNames(doc)) != 1 || len(p.BlockedVersions()) != 0 {
		t.Errorf("allowed typosquat filtered: %v %v", fileNames(doc), p.BlockedVersions())
	}
}

func TestPyPIProxyBlockedVersionsIsACopy(t *testing.T) {
	p := &PyPIProxy{}
	p.block("a", "1", "r")
	b := p.BlockedVersions()
	b[0].Reason = "mutated"
	if p.BlockedVersions()[0].Reason != "r" {
		t.Error("BlockedVersions exposed internal state")
	}
}

// direct serves one request through handle() without a listener.
func direct(t *testing.T, cfg config.Config, upstream http.HandlerFunc, method, path, accept string) (*PyPIProxy, int) {
	t.Helper()
	srv := httptest.NewServer(upstream)
	t.Cleanup(srv.Close)
	cfg.PyPI = srv.URL
	p := &PyPIProxy{cfg: cfg, client: &http.Client{Timeout: 5 * time.Second}}
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Accept", accept)
	rec := httptest.NewRecorder()
	p.handle(rec, req)
	return p, rec.Code
}

func TestPyPIProxyRoutes(t *testing.T) {
	page := serve(simplePage("pkg", [][2]string{{"pkg-1.0.tar.gz", ago(40)}}, "1.0"))
	for _, c := range []struct {
		method, path, accept string
		code                 int
	}{
		{"HEAD", "/simple/pkg/", pypiJSON, 404},
		{"POST", "/simple/pkg/", pypiJSON, 404},
		{"GET", "/simple/", pypiJSON, 404},
		{"GET", "/simple/a/b/", pypiJSON, 404},
		{"GET", "/", pypiJSON, 404},
		{"GET", "/simple/pkg/", "text/html;q=0.9, " + pypiJSON + ";q=0.5", 200},
		{"GET", "/simple/pkg/", "", 406},
	} {
		if _, code := direct(t, loopCfg(), page, c.method, c.path, c.accept); code != c.code {
			t.Errorf("%s %s (Accept %q) = %d, want %d", c.method, c.path, c.accept, code, c.code)
		}
	}
}

// The requested name is PEP 503-normalized before the upstream fetch and the
// allowlist check.
func TestPyPIProxyNormalizesName(t *testing.T) {
	var got string
	up := func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Path
		fmt.Fprint(w, simplePage("foo-bar-baz", [][2]string{{"foo_bar_baz-1.0.tar.gz", ago(1)}}, "1.0"))
	}
	cfg := loopCfg()
	cfg.Allow = []string{"foo-bar-baz"}
	p, code := direct(t, cfg, up, "GET", "/simple/Foo_Bar.baz/", pypiJSON)
	if code != 200 || got != "/simple/foo-bar-baz/" || len(p.BlockedVersions()) != 0 {
		t.Errorf("code=%d upstream path=%q blocked=%v", code, got, p.BlockedVersions())
	}
}

func TestPyPIProxyUpstreamTimeout(t *testing.T) {
	release := make(chan struct{})
	slow := func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-time.After(2 * time.Second):
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(slow))
	defer srv.Close()
	defer close(release)
	cfg := loopCfg()
	cfg.PyPI = srv.URL
	p := &PyPIProxy{cfg: cfg, client: &http.Client{Timeout: 100 * time.Millisecond}}
	req := httptest.NewRequest("GET", "/simple/pkg/", nil)
	req.Header.Set("Accept", pypiJSON)
	rec := httptest.NewRecorder()
	p.handle(rec, req)
	if rec.Code != 500 {
		t.Errorf("timeout: %d, want 500", rec.Code)
	}
}

// Concurrent requests through a live proxy (run under -race).
func TestPyPIProxyConcurrent(t *testing.T) {
	page := simplePage("pkg", [][2]string{{"pkg-1.0.tar.gz", ago(40)}, {"pkg-2.0.tar.gz", ago(1)}}, "1.0", "2.0")
	srv := httptest.NewServer(serve(page))
	defer srv.Close()
	cfg := loopCfg()
	cfg.PyPI = srv.URL
	p, err := StartPyPI(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	var wg sync.WaitGroup
	errs := make(chan string, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", p.URL()+"pkg/", nil)
			req.Header.Set("Accept", pypiJSON)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				errs <- err.Error()
				return
			}
			resp.Body.Close()
			if resp.StatusCode != 200 {
				errs <- resp.Status
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if n := len(p.BlockedVersions()); n != 20 {
		t.Errorf("blocked records = %d, want 20 (one per request)", n)
	}
}
