package lockfile

import (
	"strings"
	"testing"
)

func parseReqOK(t *testing.T, raw string) ([]Pkg, int) {
	t.Helper()
	p, n, err := parseNamed("requirements.txt", []byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p, n
}

func byKey(pkgs []Pkg) map[string]Pkg {
	m := map[string]Pkg{}
	for _, p := range pkgs {
		m[p.Key()] = p
	}
	return m
}

// Pins, extras, markers, multi-hash, continuations, inline comments and
// PEP 503 normalization all land as one PyPI registry Pkg each.
func TestParseRequirementsPins(t *testing.T) {
	raw := "# header comment\n" +
		"requests==2.31.0 \\\n" +
		"    --hash=sha256:aaa \\\n" +
		"    --hash=sha256:bbb\n" +
		"Foo_Bar.baz[socks,extra] === 1.0RC1  # trailing comment\n" +
		"colorama==0.4.6 ; sys_platform == \"win32\" --hash=sha512:ccc\n" +
		"urllib3==2.0.7\t--hash sha384:ddd\n" +
		"frag==1.0#notacomment\n"
	got, skipped := parseReqOK(t, raw)
	if skipped != 1 { // frag: '#' not preceded by whitespace stays in the spec
		t.Errorf("skipped = %d, want 1", skipped)
	}
	m := byKey(got)
	want := map[string]string{
		"requests@2.31.0":    "sha256:aaa sha256:bbb",
		"foo-bar-baz@1.0rc1": "",
		"colorama@0.4.6":     "sha512:ccc",
		"urllib3@2.0.7":      "sha384:ddd",
	}
	if len(m) != len(want) {
		t.Fatalf("got %v, want keys %v", m, want)
	}
	for k, integ := range want {
		p, ok := m[k]
		if !ok {
			t.Fatalf("missing %s in %v", k, m)
		}
		if p.Integrity != integ || !p.FromRegistry || p.Ecosystem != "pypi" || p.Conflict {
			t.Errorf("%s = %+v, want integrity %q, FromRegistry, pypi", k, p, integ)
		}
	}
	if Ecosystem(got) != "pypi" || Ecosystem([]Pkg{{Name: "a"}}) != "npm" {
		t.Error("Ecosystem helper wrong")
	}
}

// Every dependency source guard can't pin-check is counted (degraded), while
// pure option lines are silently ignored.
func TestParseRequirementsSkippedAndIgnored(t *testing.T) {
	skips := []string{
		"requests>=2.0", "requests~=2.0", "requests!=2.0", "requests<3", "requests",
		"requests==2.*", "requests==2.0,<3",
		"-e git+https://github.com/x/y.git#egg=y", "--editable ./local",
		"./local/pkg", "/abs/path/pkg.whl", "git+https://github.com/x/y.git",
		"pkg @ https://example.com/pkg-1.0.tar.gz",
		"-r other.txt", "--requirement=other.txt", "-rother.txt",
		"-c constraints.txt", "-f https://example.com/wheels", "--find-links ./wheels",
		"bad==1.0 --hash=md5:abc",
	}
	ignored := "--index-url https://pypi.org/simple\n-i https://x\n--extra-index-url https://y\n" +
		"--no-binary :all:\n--only-binary=:all:\n--pre\n--trusted-host x\n--use-feature=fast-deps\n--require-hashes\n"
	for _, s := range skips {
		got, n := parseReqOK(t, ignored+s+"\nok==1.0\n")
		if n != 1 || len(got) != 1 || got[0].Key() != "ok@1.0" {
			t.Errorf("%q: skipped=%d pkgs=%v, want 1 skipped + ok@1.0", s, n, got)
		}
	}
}

// Content with nothing recognizable must not read as "no dependencies".
func TestParseRequirementsNothingRecognized(t *testing.T) {
	if _, _, err := parseRequirements([]byte("--index-url https://pypi.org/simple\n")); err == nil ||
		!strings.Contains(err.Error(), "no entries recognized") {
		t.Errorf("err = %v, want no entries recognized", err)
	}
	// Only comments/blank: genuinely empty, not an error.
	if p, n, err := parseRequirements([]byte("# nothing\n\n")); err != nil || len(p) != 0 || n != 0 {
		t.Errorf("comment-only: %v %d %v", p, n, err)
	}
}

// The same pin recorded twice with different hashes is a hand-edited file.
func TestParseRequirementsConflict(t *testing.T) {
	got, _ := parseReqOK(t, "six==1.16.0 --hash=sha256:aaa\nsix==1.16.0 --hash=sha256:bbb\nok==1.0\n")
	m := byKey(got)
	if !m["six@1.16.0"].Conflict || m["ok@1.0"].Conflict {
		t.Errorf("conflict flags wrong: %+v", m)
	}
	// Identical duplicate lines are not a conflict.
	got, _ = parseReqOK(t, "six==1.16.0 --hash=sha256:aaa\nSix==1.16.0 --hash=sha256:aaa\n")
	if len(got) != 1 || got[0].Conflict {
		t.Errorf("identical duplicate flagged: %+v", got)
	}
}
