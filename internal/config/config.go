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
	starter := `# depguard policy (.guardrc) — committed with the repo so the whole team shares
# one policy. Every option depguard understands is listed below with its allowed
# values and default. Active lines are the defaults guard init applies; commented
# lines show optional settings (uncomment + edit to override the default).
# Full model: DESIGN.md in the depguard project.

# ── cooldown ──────────────────────────────────────────────────────────────────
# Minimum age a published version must reach before installs can see it. Most
# malicious versions are reported and yanked within days.
#   values:  <N>d (days) | <N>h (hours) | any Go duration (e.g. 336h)
#   default: 14d
cooldown: 14d

# ── ignore-scripts ────────────────────────────────────────────────────────────
# Never auto-run lifecycle scripts (postinstall &c.) — the #1 npm attack vector.
# Script-bearing packages go through the approval flow instead.
#   values:  true | false
#   default: true
ignore-scripts: true

# ── no-container-fallback ─────────────────────────────────────────────────────
# What to do when an approved build script must run but no container runtime
# (Docker/Podman) is available to sandbox it.
#   values:  warn-approve  (warn + ask; CI fails closed unless pre-approved)
#            fail          (always skip the script)
#   default: warn-approve
no-container-fallback: warn-approve

# ── registry ──────────────────────────────────────────────────────────────────
# Upstream npm registry the ephemeral proxy fetches from. Must be https (http is
# rejected except on loopback, so a malicious PR can't redirect installs).
#   values:  any https:// URL
#   default: https://registry.npmjs.org
# registry: https://registry.npmjs.org

# ── allow ─────────────────────────────────────────────────────────────────────
# Package-name patterns that bypass the cooldown entirely — your own scopes (you
# publish them; waiting is pointless). Supports a single trailing '*' glob.
#   values:  list of names/patterns, e.g. ["@yourco/*", "internal-pkg"]
#   default: []  (nothing bypasses the cooldown)
# allow: ["@yourco/*"]

# ── internal-scopes ───────────────────────────────────────────────────────────
# Scopes that must come from a PRIVATE registry — the proxy blocks them from
# resolving against the public one (dependency-confusion guard). Same '*' glob.
#   values:  list of names/patterns, e.g. ["@yourco/*"]
#   default: []  (no names treated as private)
# internal-scopes: ["@yourco/*"]

# ── flag ──────────────────────────────────────────────────────────────────────
# Diff signals 'guard check' surfaces. An explicit flag: line REPLACES the default.
#   values:  new-deps        packages a lockfile change ADDS (cheap, non-blocking)
#            new-maintainer  publisher change on installed versions (account-
#                            takeover signal; one packument fetch per package)
#            new-network /   per-version capability diff surfaced at approval time
#            new-fs
#   default: [new-deps]
# flag: [new-deps, new-maintainer]

# ── untraced-boxed ────────────────────────────────────────────────────────────
# What to do when an approved build script can only run UNTRACED (the strace
# observation image couldn't be built) — run caged-but-unwatched, or skip it.
#   values:  run | fail
#   default: run
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
		if n < 0 {
			return 0, fmt.Errorf("cooldown cannot be negative: %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d < 0 {
		// A negative cooldown moves the cutoff into the future and silently
		// disables the filter — reject it rather than fail open.
		return 0, fmt.Errorf("cooldown cannot be negative: %q", s)
	}
	return d, nil
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

// ─── policy editing (guard allow / guard config set) ─────────────────────────
//
// These let a human edit .guardrc through a command instead of hand-writing the
// flat-YAML — the same "purposeful, committed, travels with the repo" pattern as
// .guard-approvals / .guard-ignores. Every write validates against the SAME
// rules Load() enforces, so a command can never write a value Load() would later
// reject (e.g. a bad cooldown or a non-https registry).

// SetValue validates key/value and writes it into dir/.guardrc, replacing the
// existing active line for key or appending one. Returns the canonical value
// text written (e.g. a normalized list or bool). Comments and other keys are
// left untouched.
func SetValue(dir, key, value string) (string, error) {
	canon, err := canonicalValue(key, value)
	if err != nil {
		return "", err
	}
	if err := writeKeyLine(dir, key, canon); err != nil {
		return "", err
	}
	return canon, nil
}

// AddAllow adds pattern to the allow list (dedup) and persists it. Reports
// whether it was newly added (false = already present).
func AddAllow(dir, pattern string) (bool, error) {
	c, err := Load(dir)
	if err != nil {
		return false, err
	}
	for _, p := range c.Allow {
		if p == pattern {
			return false, nil
		}
	}
	list := append(append([]string{}, c.Allow...), pattern)
	if _, err := SetValue(dir, "allow", strings.Join(list, ",")); err != nil {
		return false, err
	}
	return true, nil
}

// canonicalValue validates value for key and returns the exact text to write.
// It mirrors Load()'s switch so the two never disagree about what is legal.
func canonicalValue(key, value string) (string, error) {
	value = strings.TrimSpace(value)
	switch key {
	case "cooldown":
		if _, err := parseDays(value); err != nil {
			return "", err
		}
		return value, nil
	case "ignore-scripts":
		b, err := parseBool(value)
		if err != nil {
			return "", fmt.Errorf("ignore-scripts %w", err)
		}
		return strconv.FormatBool(b), nil
	case "no-container-fallback":
		switch FallbackMode(value) {
		case FallbackWarnApprove, FallbackFail:
			return value, nil
		}
		return "", fmt.Errorf("no-container-fallback must be warn-approve or fail, got %q", value)
	case "untraced-boxed":
		if value == "run" || value == "fail" {
			return value, nil
		}
		return "", fmt.Errorf("untraced-boxed must be run or fail, got %q", value)
	case "registry":
		reg := strings.TrimSuffix(value, "/")
		if err := validateRegistry(reg); err != nil {
			return "", err
		}
		return reg, nil
	case "allow", "internal-scopes", "flag":
		// Accept comma- or space-separated input; emit a canonical [a, b] list.
		fields := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' })
		var items []string
		for _, f := range fields {
			f = strings.Trim(strings.TrimSpace(f), "\"'")
			if f != "" {
				items = append(items, f)
			}
		}
		return "[" + strings.Join(items, ", ") + "]", nil
	default:
		return "", fmt.Errorf("unknown key %q (editable: cooldown, ignore-scripts, no-container-fallback, untraced-boxed, registry, allow, internal-scopes, flag)", key)
	}
}

// writeKeyLine sets key to value in dir/.guardrc: replaces the first active
// (non-comment) line for key, or appends one if none exists. The file is
// created if absent. Preserves every other line, including comments.
func writeKeyLine(dir, key, value string) error {
	path := dir + "/" + FileName
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var lines []string
	if len(data) > 0 {
		lines = strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	}
	want := key + ": " + value
	for i, ln := range lines {
		s := strings.TrimSpace(ln)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if k, _, ok := strings.Cut(s, ":"); ok && strings.TrimSpace(k) == key {
			lines[i] = want
			return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
		}
	}
	lines = append(lines, want)
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}
