// Package config loads .guardrc — the per-repo policy file (DESIGN.md §10).
//
// The format is a deliberately tiny "flat YAML" subset (key: value, lists as
// [a, b]) parsed by hand so depguard keeps its zero-dependency guarantee.
// Anything fancier than a flat key/value file is a design smell here anyway:
// policy should stay small enough to read at a glance.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// FallbackMode controls what happens when an approved build script must run
// but no container runtime is available (DESIGN.md §9, resolved decision).
type FallbackMode string

const (
	// FallbackWarnApprove warns loudly and asks for explicit approval to run
	// uncontained. Non-interactive contexts fail closed unless pre-approved.
	FallbackWarnApprove FallbackMode = "warn-approve"
	// FallbackFail always skips the script and fails.
	FallbackFail FallbackMode = "fail"
)

// Config is the parsed .guardrc policy.
type Config struct {
	// Cooldown is the minimum age a published version must reach before the
	// proxy will let the package manager see it. Layer 1 of the defense.
	Cooldown time.Duration
	// Allow lists package-name patterns that bypass the cooldown entirely
	// (your own scopes — "@yourco/*"). '*' is only honored as a suffix.
	Allow []string
	// IgnoreScripts: when true (the default), lifecycle scripts are never
	// auto-run; script-bearing packages go through the approval flow instead.
	IgnoreScripts bool
	// NoContainerFallback picks the §9 behavior when Docker/Podman is absent.
	NoContainerFallback FallbackMode
	// Registry is the upstream npm registry the proxy fetches from.
	Registry string
	// Flag lists the diff signals `guard check` surfaces (DESIGN.md §10).
	// "new-deps" reports the packages a lockfile change ADDS to the tree;
	// "new-network" / "new-fs" are reserved for per-version capability
	// diffing (config is honored; the diff itself is a follow-up layer).
	Flag []string
	// UntracedFail: when true, an approved script that can only run UNTRACED
	// (the strace observation image couldn't be built) is skipped instead of
	// run caged-but-unwatched. Fail-closed for shops that won't accept output
	// they couldn't observe. Default false (run caged, warn).
	UntracedFail bool
	// InternalScopes are name patterns that must come from a PRIVATE registry;
	// the proxy blocks them from resolving against the public one (dependency
	// confusion). Same single-trailing-'*' glob as Allow.
	InternalScopes []string
}

// FileName is the policy file dropped by `guard init`, committed with the repo.
const FileName = ".guardrc"

// Defaults returns the policy used when no .guardrc exists yet.
func Defaults() Config {
	return Config{
		Cooldown:            14 * 24 * time.Hour,
		IgnoreScripts:       true,
		NoContainerFallback: FallbackWarnApprove,
		Registry:            "https://registry.npmjs.org",
		// new-deps is cheap and non-blocking (a lockfile diff we already have),
		// so it's on by default; an explicit `flag:` line replaces this.
		Flag: []string{"new-deps"},
	}
}

// Load reads dir/.guardrc, returning Defaults() when the file doesn't exist
// so every command works in an un-init'ed repo with safe behavior.
func Load(dir string) (Config, error) {
	c := Defaults()
	data, err := os.ReadFile(dir + "/" + FileName)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return c, err
	}
	for ln, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			return c, fmt.Errorf("%s:%d: expected 'key: value'", FileName, ln+1)
		}
		key = strings.TrimSpace(key)
		// Strip trailing comments before parsing the value.
		if i := strings.Index(val, "#"); i >= 0 {
			val = val[:i]
		}
		val = strings.TrimSpace(val)
		switch key {
		case "cooldown":
			d, err := parseDays(val)
			if err != nil {
				return c, fmt.Errorf("%s:%d: %w", FileName, ln+1, err)
			}
			c.Cooldown = d
		case "allow":
			c.Allow = parseList(val)
		case "ignore-scripts":
			b, err := parseBool(val)
			if err != nil {
				// Fail CLOSED: a typo'd security toggle ("tru", "yes") must not
				// silently disable script neutralization. Error out and let the
				// safe default stand rather than guessing the human meant off.
				return c, fmt.Errorf("%s:%d: ignore-scripts %w", FileName, ln+1, err)
			}
			c.IgnoreScripts = b
		case "flag":
			c.Flag = parseList(val)
		case "internal-scopes":
			c.InternalScopes = parseList(val)
		case "untraced-boxed":
			switch val {
			case "run":
				c.UntracedFail = false
			case "fail":
				c.UntracedFail = true
			default:
				return c, fmt.Errorf("%s:%d: untraced-boxed must be run or fail, got %q", FileName, ln+1, val)
			}
		case "no-container-fallback":
			switch FallbackMode(val) {
			case FallbackWarnApprove, FallbackFail:
				c.NoContainerFallback = FallbackMode(val)
			default:
				return c, fmt.Errorf("%s:%d: unknown fallback %q", FileName, ln+1, val)
			}
		case "registry":
			reg := strings.TrimSuffix(val, "/")
			if err := validateRegistry(reg); err != nil {
				return c, fmt.Errorf("%s:%d: %w", FileName, ln+1, err)
			}
			c.Registry = reg
		default:
			// Unknown keys don't error — an older binary reading a newer repo's
			// policy must degrade gracefully, not crash (Open/Closed). But warn,
			// because the common cause is a typo'd KNOWN key ("cooldwn"), which
			// would otherwise silently fall back to the default.
			fmt.Fprintf(os.Stderr, "guard: %s:%d: unknown key %q (ignored)\n", FileName, ln+1, key)
		}
	}
	return c, nil
}

// Allowed reports whether name matches any allow pattern, i.e. the package
// bypasses the cooldown. Patterns support a single trailing '*' glob.
func (c Config) Allowed(name string) bool {
	for _, p := range c.Allow {
		if strings.HasSuffix(p, "*") {
			if strings.HasPrefix(name, strings.TrimSuffix(p, "*")) {
				return true
			}
		} else if name == p {
			return true
		}
	}
	return false
}

// Flagged reports whether diff signal s is enabled in policy (e.g. "new-deps").
func (c Config) Flagged(s string) bool {
	for _, f := range c.Flag {
		if f == s {
			return true
		}
	}
	return false
}

// Internal reports whether name matches an internal-scope pattern — i.e. it
// must come from a private registry and must NOT resolve against the public
// one (dependency-confusion guard). Same single-trailing-'*' glob as Allowed.
func (c Config) Internal(name string) bool {
	for _, p := range c.InternalScopes {
		if strings.HasSuffix(p, "*") {
			if strings.HasPrefix(name, strings.TrimSuffix(p, "*")) {
				return true
			}
		} else if name == p {
			return true
		}
	}
	return false
}

// parseBool accepts ONLY explicit "true"/"false". Unlike strconv.ParseBool it
// rejects "1"/"yes"/"on": a security toggle should be unambiguous in a
// committed policy file, and an unrecognized value is a typo to surface, not a
// value to guess at.
func parseBool(s string) (bool, error) {
	switch s {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("expected true or false, got %q", s)
}

// WriteDefault drops a commented starter .guardrc into dir. Refuses to
// overwrite an existing policy — that's a human's call, not the tool's.
func WriteDefault(dir string) error {
	path := dir + "/" + FileName
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", FileName)
	}
	starter := `# depguard policy — committed with the repo so the whole team shares it.
# See DESIGN.md in the depguard project for the full model.

# Minimum age a published version must reach before installs can see it.
# Most malicious versions are reported and yanked within days.
cooldown: 14d

# Your own scopes bypass the cooldown (you publish them; waiting is pointless).
# allow: ["@yourco/*"]

# Never auto-run lifecycle scripts; script-bearing packages need approval.
ignore-scripts: true

# When an approved build script must run but no container runtime exists:
# warn-approve = warn + ask (CI fails closed unless pre-approved) | fail = always skip
no-container-fallback: warn-approve

# Diff signals surfaced by 'guard check'. new-deps reports packages a lockfile
# change adds (on by default); new-maintainer flags publisher changes on
# installed versions (account-takeover signal; one packument fetch per package);
# new-network/new-fs turn on the per-version capability diff at approval time.
# flag: [new-deps, new-maintainer]

# Scopes that must come from a PRIVATE registry — the proxy blocks them from
# resolving against the public one (dependency-confusion guard).
# internal-scopes: ["@yourco/*"]

# What to do when an approved build script can only run UNTRACED (no strace
# image could be built): run (caged but unwatched) | fail (skip it).
# untraced-boxed: run
`
	return os.WriteFile(path, []byte(starter), 0o644)
}

// validateRegistry rejects plaintext registries: .guardrc is committed, so a
// malicious PR could otherwise point installs at an http:// URL and open the
// whole tree to interception. Loopback http stays allowed — local proxies
// and test harnesses are not a wire-attack surface.
func validateRegistry(reg string) error {
	u, err := url.Parse(reg)
	if err != nil {
		return fmt.Errorf("bad registry URL %q", reg)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
	}
	return fmt.Errorf("registry must be https (or http on loopback), got %q", reg)
}

// parseDays understands "14d", "36h", or a bare Go duration string.
func parseDays(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, fmt.Errorf("bad cooldown %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// parseList parses [a, b, "c"] into a string slice.
func parseList(s string) []string {
	s = strings.Trim(s, "[]")
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.Trim(strings.TrimSpace(part), `"'`)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
