package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectManager(t *testing.T) {
	cases := []struct{ file, want string }{
		{"pnpm-lock.yaml", "pnpm"},
		{"yarn.lock", "yarn"},
		{"package-lock.json", "npm"},
		{"", "npm"}, // no lockfile → npm default
		{"requirements.txt", "pip"},
		{"requirements.txt,package-lock.json", "npm"}, // node lockfile wins
		{"requirements.txt,yarn.lock", "yarn"},
	}
	for _, c := range cases {
		dir := t.TempDir()
		for _, f := range strings.Split(c.file, ",") {
			if f == "" {
				continue
			}
			if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if got := detectManager(dir); got != c.want {
			t.Errorf("detectManager(%q) = %q, want %q", c.file, got, c.want)
		}
	}
}

// has reports whether args contains s.
func has(args []string, s string) bool {
	for _, a := range args {
		if a == s {
			return true
		}
	}
	return false
}

func TestBuildInstallNpm(t *testing.T) {
	inv := buildInstall("npm", "install", []string{"lodash"}, "http://127.0.0.1:9", true)
	if inv.name != "npm" {
		t.Fatalf("name = %q", inv.name)
	}
	if inv.args[0] != "install" || !has(inv.args, "lodash") {
		t.Errorf("args missing subcommand/pkg: %v", inv.args)
	}
	if !has(inv.args, "--registry=http://127.0.0.1:9") {
		t.Errorf("npm should get the --registry flag: %v", inv.args)
	}
	if !has(inv.args, "--ignore-scripts") {
		t.Errorf("ignoreScripts not applied: %v", inv.args)
	}
}

func TestBuildInstallYarnNoRegistryFlag(t *testing.T) {
	inv := buildInstall("yarn", "install", nil, "http://127.0.0.1:9", true)
	if inv.name != "yarn" {
		t.Fatalf("name = %q", inv.name)
	}
	// yarn berry rejects an unknown --registry flag → must route via env only.
	for _, a := range inv.args {
		if strings.HasPrefix(a, "--registry") {
			t.Errorf("yarn must NOT carry a --registry flag, got %v", inv.args)
		}
	}
	found := false
	for _, e := range inv.env {
		if e == "YARN_NPM_REGISTRY_SERVER=http://127.0.0.1:9" {
			found = true
		}
	}
	if !found {
		t.Errorf("yarn must route registry via env: %v", inv.env)
	}
}

func TestBuildInstallCiMapsToFrozen(t *testing.T) {
	// pnpm/yarn have no `ci` subcommand → install --frozen-lockfile.
	for _, mgr := range []string{"pnpm", "yarn"} {
		inv := buildInstall(mgr, "ci", nil, "http://x", false)
		if inv.args[0] != "install" || !has(inv.args, "--frozen-lockfile") {
			t.Errorf("%s ci should map to install --frozen-lockfile, got %v", mgr, inv.args)
		}
	}
	// npm keeps its real ci subcommand.
	if inv := buildInstall("npm", "ci", nil, "http://x", false); inv.args[0] != "ci" {
		t.Errorf("npm ci should stay `ci`, got %v", inv.args)
	}
}

func TestBuildInstallRegistryEnvAlwaysSet(t *testing.T) {
	inv := buildInstall("npm", "install", nil, "http://reg", false)
	want := "npm_config_registry=http://reg"
	found := false
	for _, e := range inv.env {
		if e == want {
			found = true
		}
	}
	if !found {
		t.Errorf("npm_config_registry env not set: %v", inv.env)
	}
}

// pip: index points at the proxy, wheels only unless scripts are allowed
// (--allow-sdist), ci installs requirements.txt.
func TestBuildInstallPip(t *testing.T) {
	inv := buildInstall("pip", "install", []string{"requests"}, "http://127.0.0.1:9/simple/", true)
	want := []string{"install", "--index-url", "http://127.0.0.1:9/simple/", "--only-binary=:all:", "requests"}
	if inv.name != "pip" || strings.Join(inv.args, " ") != strings.Join(want, " ") || inv.env != nil {
		t.Errorf("pip install = %s %v env=%v", inv.name, inv.args, inv.env)
	}
	inv = buildInstall("pip", "ci", nil, "http://x/simple/", true)
	if !has(inv.args, "--only-binary=:all:") || strings.Join(inv.args[len(inv.args)-2:], " ") != "-r requirements.txt" {
		t.Errorf("pip ci = %v", inv.args)
	}
	if inv := buildInstall("pip", "install", []string{"x"}, "http://x/simple/", false); has(inv.args, "--only-binary=:all:") {
		t.Errorf("allow-sdist still forces wheels: %v", inv.args)
	}
}

func TestPipEnvAndPackageArgs(t *testing.T) {
	env := pipEnv([]string{"PATH=/bin", "PIP_INDEX_URL=https://evil", "PIP_EXTRA_INDEX_URL=https://evil", "PIP_NO_CACHE_DIR=1"})
	if strings.Join(env, ",") != "PATH=/bin,PIP_NO_CACHE_DIR=1" {
		t.Errorf("pipEnv = %v", env)
	}
	got := pipPackageArgs([]string{"--upgrade", "requests", "-r", "req.txt", "--target", "/tmp/x", "flask==3.0"})
	if strings.Join(got, ",") != "requests,flask==3.0" {
		t.Errorf("pipPackageArgs = %v", got)
	}
}

// User flags that re-route pip's index or re-enable sdists are refused.
func TestPipArgBlocker(t *testing.T) {
	refused := [][]string{
		{"--index-url", "https://evil/simple"}, {"--index-url=https://evil/simple"},
		{"-i", "https://evil"}, {"-ihttps://evil"},
		{"--extra-index-url", "https://evil"}, {"--extra-index-url=https://evil"},
		{"--find-links", "./wheels"}, {"--find-links=./wheels"}, {"-f", "./w"}, {"-f./w"},
		{"requests", "--no-index"},
		{"--no-binary", ":all:"}, {"--no-binary=:all:"},
	}
	for _, args := range refused {
		if err := pipArgBlocker(args, false); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
	if err := pipArgBlocker([]string{"--no-binary=:all:"}, true); err != nil {
		t.Errorf("--no-binary with --allow-sdist refused: %v", err)
	}
	if err := pipArgBlocker([]string{"--extra-index-url=x"}, true); err == nil {
		t.Error("--allow-sdist must not unlock an extra index")
	}
	ok := []string{"--only-binary=:all:", "-r", "requirements.txt", "-t", "/tmp/x", "--upgrade", "-U", "requests", "flask==3.0", "--target=/tmp/y"}
	if err := pipArgBlocker(ok, false); err != nil {
		t.Errorf("benign args refused: %v", err)
	}
}

func TestPipFailHint(t *testing.T) {
	nomatch := "ERROR: No matching distribution found for x"
	if h := pipFailHint(nomatch, true, 0); !strings.Contains(h, "--allow-sdist") {
		t.Errorf("no blocks: %q", h)
	}
	if h := pipFailHint(nomatch, true, 2); strings.Contains(h, "--allow-sdist") || !strings.Contains(h, "hidden versions above") {
		t.Errorf("with blocks: %q", h)
	}
	if pipFailHint(nomatch, false, 0) != "" || pipFailHint("network error", true, 0) != "" {
		t.Error("hint without wheels-only or without a resolution failure")
	}
}

func TestBuildInstallPipShapes(t *testing.T) {
	inv := buildInstall("pip", "install", []string{"-r", "other.txt", "x"}, "http://p/simple/", true)
	if inv.args[1] != "--index-url" || inv.args[2] != "http://p/simple/" {
		t.Errorf("proxy must be the first --index-url: %v", inv.args)
	}
	if strings.Count(strings.Join(inv.args, " "), "--index-url") != 1 || !has(inv.args, "other.txt") || has(inv.args, "requirements.txt") {
		t.Errorf("install args = %v", inv.args)
	}
	inv = buildInstall("pip", "ci", []string{"--no-deps"}, "http://p/simple/", false)
	if has(inv.args, "--only-binary=:all:") || !has(inv.args, "requirements.txt") || inv.args[len(inv.args)-1] != "--no-deps" {
		t.Errorf("ci args = %v", inv.args)
	}
	args, allow := splitAllowSdist([]string{"--allow-sdist", "x", "--allow-sdist"})
	if !allow || strings.Join(args, " ") != "x" {
		t.Errorf("splitAllowSdist = %v %v", args, allow)
	}
	if args, allow := splitAllowSdist([]string{"x"}); allow || len(args) != 1 {
		t.Errorf("no flag: %v %v", args, allow)
	}
}

func TestPipEnvEdges(t *testing.T) {
	env := pipEnv([]string{"PIP_INDEX_URL_X=1", "PIP_NO_CACHE_DIR=", "PIP_INDEX_URL=a", "PIP_INDEX_URL=b", "PIP_EXTRA_INDEX_URL=c", "PIP_EXTRA_INDEX_URL=d"})
	if strings.Join(env, ",") != "PIP_INDEX_URL_X=1,PIP_NO_CACHE_DIR=" {
		t.Errorf("pipEnv = %v", env)
	}
}

func TestPipPackageArgsTable(t *testing.T) {
	for in, want := range map[string]string{
		"pkg==1.0":             "pkg==1.0",
		"pkg[extra]>=1":        "pkg[extra]>=1",
		"-r req.txt pkg":       "pkg",
		"--target=dir pkg":     "pkg",
		"-U pkg":               "pkg",
		"--index-url u a b":    "a,b",
		"-e ./local --no-deps": "",
		"":                     "",
	} {
		if got := strings.Join(pipPackageArgs(strings.Fields(in)), ","); got != want {
			t.Errorf("pipPackageArgs(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPipArgBlockerEdges(t *testing.T) {
	for _, c := range []struct {
		args    string
		sdistOK bool
		refused bool
	}{
		{"--index-url=", false, true},
		{"--no-binary=:all:", false, true},
		{"--only-binary=:none:", false, true},
		{"--only-binary :none:", false, true},
		{"--only-binary=:none:", true, false},
		{"--only-binary=numpy", false, false},
		{"--only-binary :all:", false, false},
		{"--prefer-binary", false, false},
		{"-I pkg", false, false}, // --ignore-installed, not -i
	} {
		if err := pipArgBlocker(strings.Fields(c.args), c.sdistOK); (err != nil) != c.refused {
			t.Errorf("%q sdistOK=%v: err=%v, want refused=%v", c.args, c.sdistOK, err, c.refused)
		}
	}
}

func TestPipFailHintTable(t *testing.T) {
	both := "--only-binary ... No matching distribution found"
	for _, c := range []struct {
		out        string
		onlyBinary bool
		blocked    int
		want       string // substring; "" = no hint
	}{
		{both, true, 0, "--allow-sdist"},
		{"ERROR: network unreachable", true, 0, ""},
		{both, false, 3, ""},
		{"Could not find a version (only-binary)", true, 0, "--allow-sdist"},
		{both, true, 1, "hidden versions"},
	} {
		got := pipFailHint(c.out, c.onlyBinary, c.blocked)
		if (c.want == "" && got != "") || (c.want != "" && !strings.Contains(got, c.want)) {
			t.Errorf("pipFailHint(%q, %v, %d) = %q, want %q", c.out, c.onlyBinary, c.blocked, got, c.want)
		}
	}
}
