// Package sdist is the fetch-and-inspect half of guard's source-distribution
// handling (DESIGN.md §8, pip). An sdist runs setup.py / a PEP 517 backend at
// build time, so guard fetches its bytes itself (hash-verified), reads its
// build requirements, and decides which version satisfies pip's request —
// all without executing anything. The trial build happens in the box.
package sdist

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"depguard/internal/pyver"
)

// Fetch downloads an sdist and returns its bytes only when their sha256 equals
// sha256hex (from the index page). A missing digest, a mismatch, a non-200 or a
// body over capBytes is an error — never partial or unverified bytes.
func Fetch(client *http.Client, url, sha256hex string, capBytes int64) ([]byte, error) {
	if sha256hex == "" {
		return nil, fmt.Errorf("no sha256 for %s on the index page — refusing unverifiable bytes", url)
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sdist fetch returned %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, capBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > capBytes {
		return nil, fmt.Errorf("sdist exceeds the %d MiB cap", capBytes>>20)
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, sha256hex) {
		return nil, fmt.Errorf("sdist sha256 mismatch: page says %s, got %s", sha256hex, got)
	}
	return b, nil
}

// Build is what an sdist says about how it builds.
type Build struct {
	// Requires is [build-system] requires — pip's legacy setuptools default
	// when the sdist has no pyproject.toml or no [build-system] table.
	Requires []string
	// Backend is build-backend ("" = legacy setup.py through setuptools).
	Backend string
	// InTree: backend-path is set — the backend ships inside the sdist.
	InTree bool
	// SetupPy: a setup.py sits at the sdist root (build-time code).
	SetupPy bool
}

// legacyRequires is pip's default for an sdist without a [build-system] table.
var legacyRequires = []string{"setuptools>=40.8.0", "wheel"}

// maxInspectBytes bounds decompression while looking for root files.
var maxInspectBytes int64 = 256 << 20

// BuildRequires reads <root>/pyproject.toml and <root>/setup.py from a .tar.gz
// sdist. Only the [build-system] table is parsed; malformed values there are
// an error (a build guard can't reason about isn't approved by accident).
func BuildRequires(tgz []byte) (Build, error) {
	gz, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		return Build{}, fmt.Errorf("sdist is not gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, maxInspectBytes))
	var b Build
	var pyproject []byte
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Build{}, fmt.Errorf("sdist tar: %w", err)
		}
		_, rel, ok := strings.Cut(strings.TrimPrefix(hdr.Name, "./"), "/")
		if !ok || hdr.Typeflag != tar.TypeReg {
			continue
		}
		switch rel {
		case "setup.py":
			b.SetupPy = true
		case "pyproject.toml":
			if pyproject, err = io.ReadAll(io.LimitReader(tr, 1<<20)); err != nil {
				return Build{}, err
			}
		}
	}
	if pyproject == nil {
		b.Requires = legacyRequires
		return b, nil
	}
	return parseBuildSystem(string(pyproject), b)
}

// parseBuildSystem fills b from the [build-system] table of a pyproject.toml.
// A minimal reader on purpose: keys requires / build-backend / backend-path only.
func parseBuildSystem(toml string, b Build) (Build, error) {
	body, found := buildSystemTable(toml)
	if !found {
		b.Requires = legacyRequires
		return b, nil
	}
	sawRequires := false
	for len(body) > 0 {
		line, rest, _ := strings.Cut(body, "\n")
		key, val, isKV := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !isKV || strings.HasPrefix(key, "#") {
			body = rest
			continue
		}
		val = strings.TrimSpace(val)
		switch key {
		case "requires", "backend-path":
			arr, after, err := parseStringArray(val + "\n" + rest)
			if err != nil {
				return Build{}, fmt.Errorf("pyproject.toml [build-system] %s: %w", key, err)
			}
			if key == "requires" {
				b.Requires, sawRequires = arr, true
			} else {
				b.InTree = true
			}
			body = after
			continue
		case "build-backend":
			s, _, err := parseString(val)
			if err != nil {
				return Build{}, fmt.Errorf("pyproject.toml build-backend: %w", err)
			}
			b.Backend = s
		}
		body = rest
	}
	if !sawRequires {
		return Build{}, errors.New("pyproject.toml [build-system] has no requires")
	}
	// These strings come from the untrusted sdist and become pip argv: an option
	// ("--index-url=…") or a direct reference ("x @ https://…") would route
	// around the proxy, so anything but a plain requirement refuses the sdist.
	for _, r := range b.Requires {
		if !ValidRequirement(r) {
			return Build{}, fmt.Errorf("build requirement %q is not a plain PEP 508 requirement", r)
		}
	}
	return b, nil
}

// plainReqRe is name[extras] <specifier set> ; <marker> — no URL, path, or
// option shape. The marker may hold anything but a backslash or newline; it
// can't change what pip fetches, only whether the requirement applies.
var plainReqRe = func() *regexp.Regexp {
	name := `[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?`
	spec := `(?:===|~=|==|!=|<=|>=|<|>)\s*[A-Za-z0-9.*+!_-]+`
	return regexp.MustCompile(`^` + name + `\s*(?:\[\s*` + name + `(?:\s*,\s*` + name + `)*\s*\])?` +
		`\s*(?:` + spec + `(?:\s*,\s*` + spec + `)*)?\s*(?:;[^\\\n]*)?$`)
}()

// ValidRequirement reports whether s is a plain PEP 508 requirement that can
// safely be handed to pip as one argv element.
func ValidRequirement(s string) bool { return plainReqRe.MatchString(s) }

// buildSystemTable returns the text between the [build-system] header and the
// next table header.
func buildSystemTable(toml string) (string, bool) {
	lines := strings.Split(strings.ReplaceAll(toml, "\r\n", "\n"), "\n")
	for i, l := range lines {
		if strings.TrimSpace(l) != "[build-system]" {
			continue
		}
		end := len(lines)
		for j := i + 1; j < len(lines); j++ {
			if t := strings.TrimSpace(lines[j]); strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") && !strings.ContainsAny(t, `"'`) {
				end = j
				break
			}
		}
		return strings.Join(lines[i+1:end], "\n"), true
	}
	return "", false
}

// parseStringArray parses a TOML array of strings at the start of s (which may
// span lines, with comments and a trailing comma) and returns the rest after ']'.
func parseStringArray(s string) ([]string, string, error) {
	s = strings.TrimLeft(s, " \t")
	if !strings.HasPrefix(s, "[") {
		return nil, "", errors.New("expected an array")
	}
	s = s[1:]
	out := []string{}
	for {
		s = strings.TrimLeft(s, " \t\r\n,")
		switch {
		case s == "":
			return nil, "", errors.New("unterminated array")
		case s[0] == ']':
			_, rest, _ := strings.Cut(s[1:], "\n")
			return out, rest, nil
		case s[0] == '#':
			_, s, _ = strings.Cut(s, "\n")
		default:
			str, rest, err := parseString(s)
			if err != nil {
				return nil, "", err
			}
			out, s = append(out, str), rest
		}
	}
}

// parseString reads one basic ("...") or literal ('...') TOML string.
func parseString(s string) (string, string, error) {
	if s == "" || (s[0] != '"' && s[0] != '\'') {
		return "", "", errors.New("expected a quoted string")
	}
	q := s[0]
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch {
		case s[i] == q:
			return b.String(), s[i+1:], nil
		case s[i] == '\n':
			return "", "", errors.New("unterminated string")
		case q == '"' && s[i] == '\\' && i+1 < len(s):
			i++
			b.WriteByte(s[i])
		default:
			b.WriteByte(s[i])
		}
	}
	return "", "", errors.New("unterminated string")
}

// Satisfies reports whether a Stable version meets a PEP 440 specifier set
// (comma-joined ==, ==X.*, !=, <, <=, >, >=, ~=). An empty spec matches all.
// Shapes this minimal comparator can't judge (pre-releases, ===, local
// versions) are an error, so the caller asks the user to pin instead of guessing.
func Satisfies(version, spec string) (bool, error) {
	if !pyver.Stable(version) {
		return false, fmt.Errorf("version %q is not a plain release", version)
	}
	for _, clause := range strings.Split(spec, ",") {
		clause = strings.TrimSpace(clause)
		if clause == "" {
			continue
		}
		ok, err := satisfiesOne(version, clause)
		if err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

func satisfiesOne(v, clause string) (bool, error) {
	var op string
	for _, o := range []string{"===", "~=", "==", "!=", "<=", ">=", "<", ">"} {
		if strings.HasPrefix(clause, o) {
			op = o
			break
		}
	}
	target := strings.TrimSpace(strings.TrimPrefix(clause, op))
	if op == "" || op == "===" {
		return false, fmt.Errorf("unsupported specifier %q", clause)
	}
	if prefix, wild := strings.CutSuffix(target, ".*"); wild {
		if (op != "==" && op != "!=") || !pyver.Stable(prefix) {
			return false, fmt.Errorf("unsupported specifier %q", clause)
		}
		return hasPrefix(v, prefix) == (op == "=="), nil
	}
	if !pyver.Stable(target) {
		return false, fmt.Errorf("unsupported specifier %q", clause)
	}
	c := pyver.Compare(v, target)
	switch op {
	case "==":
		return c == 0, nil
	case "!=":
		return c != 0, nil
	case "<":
		return c < 0, nil
	case "<=":
		return c <= 0, nil
	case ">":
		return c > 0, nil
	case ">=":
		return c >= 0, nil
	}
	// ~=X.Y.Z means >=X.Y.Z and ==X.Y.*
	parts := strings.Split(target, ".")
	if len(parts) < 2 {
		return false, fmt.Errorf("~= needs at least two release parts: %q", clause)
	}
	return c >= 0 && hasPrefix(v, strings.Join(parts[:len(parts)-1], ".")), nil
}

// hasPrefix reports whether v's release parts start with prefix's (missing
// parts of v count as 0, so 1 matches 1.0.*).
func hasPrefix(v, prefix string) bool {
	vp, pp := strings.Split(v, "."), strings.Split(prefix, ".")
	for i, p := range pp {
		x := "0"
		if i < len(vp) {
			x = vp[i]
		}
		if pyver.Compare(x, p) != 0 {
			return false
		}
	}
	return true
}

var (
	ansiRe     = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	noMatchRe  = regexp.MustCompile(`(?m)No matching distribution found for (.+)$`)
	couldNotRe = regexp.MustCompile(`(?m)Could not find a version that satisfies the requirement (.+?)(?: \(from |$)`)
	reqRe      = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$`)
)

// NeedSdist reads a failed `pip download --only-binary=:all:` and returns the
// requirement pip could not satisfy from wheels: the PEP 503-normalized name and
// the raw specifier ("" = any version). ok=false when the failure is something
// else (network, a typo'd flag, ...).
func NeedSdist(pipOutput string) (pkg, spec string, ok bool) {
	out := ansiRe.ReplaceAllString(pipOutput, "")
	var req string
	if m := noMatchRe.FindAllStringSubmatch(out, -1); m != nil {
		req = m[len(m)-1][1]
	} else if m := couldNotRe.FindStringSubmatch(out); m != nil {
		req = m[1]
	} else {
		return "", "", false
	}
	req, _, _ = strings.Cut(strings.TrimSpace(req), ";")
	m := reqRe.FindStringSubmatch(strings.TrimSpace(req))
	if m == nil {
		return "", "", false
	}
	return pyver.NormalizeName(m[1]), strings.ReplaceAll(strings.TrimSpace(m[2]), " ", ""), true
}
