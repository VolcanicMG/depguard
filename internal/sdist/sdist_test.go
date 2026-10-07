package sdist

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// tgz builds a gzipped tar from name → content (names include the sdist root).
func tgz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body)) //nolint:errcheck
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestFetch(t *testing.T) {
	body := []byte("sdist bytes")
	sum := sha256.Sum256(body)
	good := hex.EncodeToString(sum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			w.WriteHeader(404)
			return
		}
		w.Write(body) //nolint:errcheck
	}))
	defer srv.Close()
	c := srv.Client()
	if b, err := Fetch(c, srv.URL+"/x.tar.gz", strings.ToUpper(good), 1<<20); err != nil || string(b) != string(body) {
		t.Errorf("good fetch: %q %v", b, err)
	}
	for name, call := range map[string]func() error{
		"mismatch": func() error { _, err := Fetch(c, srv.URL+"/x", strings.Repeat("0", 64), 1<<20); return err },
		"no hash":  func() error { _, err := Fetch(c, srv.URL+"/x", "", 1<<20); return err },
		"oversize": func() error { _, err := Fetch(c, srv.URL+"/x", good, 4); return err },
		"404":      func() error { _, err := Fetch(c, srv.URL+"/missing", good, 1<<20); return err },
	} {
		if call() == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestBuildRequires(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  Build
	}{
		{"no pyproject → legacy default + setup.py fact",
			map[string]string{"pkg-1.0/setup.py": "x", "pkg-1.0/pkg/__init__.py": ""},
			Build{Requires: legacyRequires, SetupPy: true}},
		{"pyproject without [build-system] → legacy default",
			map[string]string{"pkg-1.0/pyproject.toml": "[tool.black]\nline-length = 88\n"},
			Build{Requires: legacyRequires}},
		{"multi-line requires, comments, both quote styles, trailing comma",
			map[string]string{"pkg-1.0/pyproject.toml": "[project]\nname = \"pkg\"\n\n[build-system]\nrequires = [\n  \"setuptools>=61\",  # modern\n  'wheel',\n]\nbuild-backend = \"setuptools.build_meta\"  # std\n\n[tool.x]\nrequires = [\"not-this\"]\n"},
			Build{Requires: []string{"setuptools>=61", "wheel"}, Backend: "setuptools.build_meta"}},
		{"in-tree backend",
			map[string]string{"pkg-1.0/pyproject.toml": "[build-system]\nrequires = []\nbuild-backend = \"backend\"\nbackend-path = [\".\"]\n", "pkg-1.0/backend.py": ""},
			Build{Requires: []string{}, Backend: "backend", InTree: true}},
		{"nested pyproject is not the root one",
			map[string]string{"pkg-1.0/sub/pyproject.toml": "[build-system]\nrequires = [\"x\"]\n", "pkg-1.0/setup.py": ""},
			Build{Requires: legacyRequires, SetupPy: true}},
	}
	for _, c := range cases {
		got, err := BuildRequires(tgz(t, c.files))
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %+v %v, want %+v", c.name, got, err, c.want)
		}
	}
}

func TestBuildRequiresMalformed(t *testing.T) {
	for name, toml := range map[string]string{
		"unterminated array":  "[build-system]\nrequires = [\"a\",\n",
		"bare word in array":  "[build-system]\nrequires = [setuptools]\n",
		"unterminated string": "[build-system]\nrequires = [\"a]\n",
		"no requires":         "[build-system]\nbuild-backend = \"x\"\n",
		"requires not array":  "[build-system]\nrequires = \"setuptools\"\n",
	} {
		if _, err := BuildRequires(tgz(t, map[string]string{"p-1/pyproject.toml": toml})); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if _, err := BuildRequires([]byte("not gzip")); err == nil {
		t.Error("non-gzip: want an error")
	}
}

func TestSatisfies(t *testing.T) {
	for _, c := range []struct {
		v, spec string
		want    bool
	}{
		{"1.0", "", true}, {"1.0", "==1.0", true}, {"1.0.0", "==1.0", true}, {"1.1", "==1.0", false},
		{"1.4", "==1.*", true}, {"2.0", "==1.*", false}, {"1", "==1.0.*", true}, {"1.0.5", "==1.0.*", true},
		{"1.4", "!=1.4", false}, {"1.5", "!=1.*", false}, {"2.0", "!=1.*", true},
		{"1.9", "<2", true}, {"2.0", "<2", false}, {"2.0", "<=2", true}, {"2.0.1", ">2", true}, {"2", ">=2.0", true},
		{"1.4.5", "~=1.4.2", true}, {"1.5.0", "~=1.4.2", false}, {"1.4.1", "~=1.4.2", false}, {"1.9", "~=1.4", true}, {"2.0", "~=1.4", false},
		{"1.5", ">=1, <2", true}, {"2.5", ">=1,<2", false}, {"1.5", ">=1,!=1.5", false},
	} {
		got, err := Satisfies(c.v, c.spec)
		if err != nil || got != c.want {
			t.Errorf("Satisfies(%s, %q) = %v, %v; want %v", c.v, c.spec, got, err, c.want)
		}
	}
	for _, bad := range [][2]string{{"1.0", "===1.0"}, {"1.0", "~=1"}, {"1.0", ">=1.0rc1"}, {"1.0", "<1.*"}, {"1.0", "1.0"}, {"1.0rc1", ">=1"}, {"1.0", ">=1.0+local"}} {
		if _, err := Satisfies(bad[0], bad[1]); err == nil {
			t.Errorf("Satisfies(%s, %q): want an error", bad[0], bad[1])
		}
	}
}

func TestNeedSdist(t *testing.T) {
	for out, want := range map[string][2]string{
		"ERROR: Could not find a version that satisfies the requirement src-only (from versions: none)\nERROR: No matching distribution found for src-only\n": {"src-only", ""},
		"ERROR: Could not find a version that satisfies the requirement Dep_Pkg<2 (from parent==1.0) (from versions: none)":                                   {"dep-pkg", "<2"},
		"ERROR: No matching distribution found for foo[extra]>=1.0, <2 ; python_version >= \"3.8\"":                                                           {"foo", ">=1.0,<2"},
		"\x1b[31mERROR: No matching distribution found for Bar==1.2\x1b[0m":                                                                                   {"bar", "==1.2"},
	} {
		pkg, spec, ok := NeedSdist(out)
		if !ok || pkg != want[0] || spec != want[1] {
			t.Errorf("NeedSdist(%q) = %q %q %v, want %v", out, pkg, spec, ok, want)
		}
	}
	for _, out := range []string{"", "ERROR: Could not install packages due to an OSError: [Errno 101] Network is unreachable", "no such option: --target"} {
		if _, _, ok := NeedSdist(out); ok {
			t.Errorf("NeedSdist(%q) matched", out)
		}
	}
}

func TestValidRequirement(t *testing.T) {
	for _, ok := range []string{
		"setuptools>=40.8.0", "wheel", `Cython<3; python_version<"3.12"`, "pkg[extra1,extra2]==1.0",
		"hatchling", "scikit-build-core >= 0.4, < 1", "foo===1.0", "foo~=1.4", `bar; platform_machine == "x86-64"`,
	} {
		if !ValidRequirement(ok) {
			t.Errorf("rejected %q", ok)
		}
	}
	for _, bad := range []string{
		"--index-url=http://evil", "-r", "/x", "-e .", "foo @ https://evil/foo.whl", "foo @ file:///tmp/x",
		"https://evil/foo.whl", "./local", `C:\x`, " foo", "", "foo bar", "foo>=1 --hash=sha256:aa",
		"foo>=1\n--index-url=x", "git" + "+https://h/x.git", `foo; \evil`,
	} {
		if ValidRequirement(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}

// An option or direct reference smuggled into [build-system] requires refuses the sdist.
func TestBuildRequiresRejectsSmuggledArgs(t *testing.T) {
	for _, req := range []string{`"--index-url=http://evil"`, `"-r", "/x"`, `"foo @ https://evil/foo.whl"`} {
		toml := "[build-system]\nrequires = [" + req + "]\n"
		if _, err := BuildRequires(tgz(t, map[string]string{"p-1/pyproject.toml": toml})); err == nil || !strings.Contains(err.Error(), "not a plain PEP 508 requirement") {
			t.Errorf("%s: err = %v", req, err)
		}
	}
}
