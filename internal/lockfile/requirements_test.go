package lockfile

import (
	"strconv"
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

const (
	hA = "sha256:" + "aa"
	hB = "sha256:" + "bb"
	hC = "sha512:" + "cc"
)

// reqCase is one requirements.txt snippet: the pins it must yield ("key|integrity")
// and how many entries it must count as skipped.
type reqCase struct {
	name    string
	raw     string
	pins    []string
	skipped int
}

func runReqCases(t *testing.T, cases []reqCase) {
	t.Helper()
	for _, c := range cases {
		got, n, err := parseNamed("requirements.txt", []byte(c.raw))
		if err != nil {
			t.Errorf("%s: err %v", c.name, err)
			continue
		}
		var keys []string
		for _, p := range got {
			keys = append(keys, p.Key()+"|"+p.Integrity)
		}
		if strings.Join(keys, ",") != strings.Join(c.pins, ",") || n != c.skipped {
			t.Errorf("%s: pins %v skipped %d, want %v skipped %d", c.name, keys, n, c.pins, c.skipped)
		}
	}
}

func TestRequirementsWhitespaceAndComments(t *testing.T) {
	runReqCases(t, []reqCase{
		{"CRLF", "a==1.0\r\nb==2.0 --hash=" + hA + "\r\n", []string{"a@1.0|", "b@2.0|" + hA}, 0},
		{"BOM", "\ufeffa==1.0\n", []string{"a@1.0|"}, 0},
		{"tabs around ==", "a\t==\t1.0\n", []string{"a@1.0|"}, 0},
		{"trailing whitespace", "a==1.0   \t\n", []string{"a@1.0|"}, 0},
		{"blank line breaks a continuation", "a==1.0 \\\n\n--hash=" + hA + "\n", []string{"a@1.0|"}, 1},
		{"continuation into a comment", "a==1.0 \\\n# note\nb==2.0\n", []string{"a@1.0|", "b@2.0|"}, 0},
		{"comment after continued hashes", "a==1.0 \\\n  --hash=" + hA + " \\\n  --hash=" + hB + "  # via x\n", []string{"a@1.0|" + hA + " " + hB}, 0},
		{"# inside a URL is not a comment", "x @ https://h/x.zip#frag\n", nil, 1},
		{"inline comment", "a==1.0  # pinned\n", []string{"a@1.0|"}, 0},
		{"bare #", "#\na==1.0\n", []string{"a@1.0|"}, 0},
	})
}

func TestRequirementsPinShapes(t *testing.T) {
	runReqCases(t, []reqCase{
		{"uppercase", "Django==4.2\n", []string{"django@4.2|"}, 0},
		{"epoch", "a==1!2.0\n", []string{"a@1!2.0|"}, 0},
		{"local", "torch==2.1.0+cpu\n", []string{"torch@2.1.0+cpu|"}, 0},
		{"rc", "a==1.0rc1\n", []string{"a@1.0rc1|"}, 0},
		{"alpha", "a==1.0a1\n", []string{"a@1.0a1|"}, 0},
		{"dev", "a==1.0.dev3\n", []string{"a@1.0.dev3|"}, 0},
		{"post", "a==1.0.post1\n", []string{"a@1.0.post1|"}, 0},
		{"arbitrary ===", "a===weird.1\n", []string{"a@weird.1|"}, 0},
		{"spaces around ==", "a == 1.0\n", []string{"a@1.0|"}, 0},
		{"extras list", "a[x, y]==1\n", []string{"a@1|"}, 0},
		{"space before extras", "a [x]==1\n", []string{"a@1|"}, 0},
		{"marker no space", "a==1.0;python_version<\"3.9\"\n", []string{"a@1.0|"}, 0},
		{"marker with dashes", "a==1.0 ; platform_machine == \"x86-64\" --hash=" + hA + "\n", []string{"a@1.0|" + hA}, 0},
		{"--hash space form", "a==1.0 --hash " + hA + "\n", []string{"a@1.0|" + hA}, 0},
		{"mixed algs", "a==1.0 --hash=" + hC + " --hash=" + hA + "\n", []string{"a@1.0|" + hA + " " + hC}, 0},
		{"three hashes", "a==1.0 --hash=" + hB + " --hash=" + hA + " --hash=" + hC + "\n", []string{"a@1.0|" + hA + " " + hB + " " + hC}, 0},
	})
}

func TestRequirementsSkippedShapes(t *testing.T) {
	for _, s := range []string{
		"a==1.0.*", "a~=1.0", "a>=1,<2", "a!=1.0", "a", "a>=1 --hash=" + hA,
		"a @ https://h/a.whl --hash=" + hA, "./pkg.whl", "file:///x/a.whl",
		"git" + "+https://h/a.git#egg=a", "-e .", "-e git" + "+https://h/a.git#egg=a",
		"-r a.txt", "-ra.txt", "--requirement=a.txt", "-c c.txt", "-f https://h/w",
		"--find-links=x", "--hash=" + hA,
		"a==1.0 --hash=sha256:zz", "a==1.0 --hash=md5:aa", "a==1.0 --hash=sha256", "a==1.0 --hash=",
	} {
		runReqCases(t, []reqCase{{s, s + "\nok==1\n", []string{"ok@1|"}, 1}})
	}
}

func TestRequirementsOptionLinesIgnored(t *testing.T) {
	for _, s := range []string{
		"--index-url https://h", "-i https://h", "--extra-index-url https://h", "--pre",
		"--no-binary :all:", "--only-binary=:all:", "--trusted-host h", "--use-feature=x",
		"--require-hashes", "--prefer-binary", "--no-deps", "--whatever",
	} {
		runReqCases(t, []reqCase{{s, s + "\nok==1\n", []string{"ok@1|"}, 0}})
	}
}

func TestRequirementsDedupe(t *testing.T) {
	conflict := func(raw string) bool {
		got, _ := parseReqOK(t, raw)
		return len(got) == 1 && got[0].Conflict
	}
	if got, _ := parseReqOK(t, "a==1.0\na==1.0\n"); len(got) != 1 || got[0].Conflict {
		t.Errorf("identical lines: %+v", got)
	}
	if !conflict("Foo==1.0 --hash=" + hA + "\nfoo==1.0 --hash=" + hB + "\n") {
		t.Error("normalized names with different hashes must conflict")
	}
	if got, _ := parseReqOK(t, "a==1.0\na==2.0\n"); len(got) != 2 || got[0].Conflict || got[1].Conflict {
		t.Errorf("two versions: %+v", got)
	}
	if !conflict("a==1.0 --hash="+hA+"\na==1.0\n") || !conflict("a==1.0\na==1.0 --hash="+hA+"\n") {
		t.Error("hashed + unhashed duplicate must conflict (either order)")
	}
	if conflict("a==1.0 --hash=" + hA + " --hash=" + hB + "\na==1.0 --hash=" + hB + " --hash=" + hA + "\n") {
		t.Error("same hashes in a different order must not conflict")
	}
}

func TestRequirementsFiles(t *testing.T) {
	if p, n, err := parseRequirements(nil); err != nil || len(p) != 0 || n != 0 {
		t.Errorf("empty: %v %d %v", p, n, err)
	}
	var b strings.Builder
	for i := 0; i < 5000; i++ {
		b.WriteString("pkg" + strconv.Itoa(i) + "==1." + strconv.Itoa(i) + " --hash=" + hA + "\n")
	}
	if p, n, err := parseRequirements([]byte(b.String())); err != nil || len(p) != 5000 || n != 0 {
		t.Errorf("5000 lines: %d pkgs, %d skipped, %v", len(p), n, err)
	}
}

func TestNormalizePyName(t *testing.T) {
	for in, want := range map[string]string{"Foo_Bar.baz": "foo-bar-baz", "A--B": "a-b", "a.b.c": "a-b-c", "A_B-c.D": "a-b-c-d"} {
		if got := normalizePyName(in); got != want {
			t.Errorf("normalizePyName(%q) = %q, want %q", in, got, want)
		}
	}
}
