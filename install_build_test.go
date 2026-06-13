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
	}
	for _, c := range cases {
		dir := t.TempDir()
		if c.file != "" {
			if err := os.WriteFile(filepath.Join(dir, c.file), []byte("x"), 0o644); err != nil {
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
