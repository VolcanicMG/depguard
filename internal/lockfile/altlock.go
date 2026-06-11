package lockfile

// Hand-rolled parsers for pnpm-lock.yaml and yarn.lock. depguard's zero-dep
// invariant rules out a YAML library, but we don't need general YAML: both
// formats are line-regular, and we only need name@version (+ integrity) for
// the advisory/cooldown/integrity checks — not the full dependency graph npm's
// own lockfile gives us. These are deliberately tolerant: an unrecognized line
// is skipped, never fatal, because a check must degrade gracefully.

import "strings"

// parsePnpm extracts installed packages from a pnpm-lock.yaml. It reads the
// `packages:` section, whose 2-space-indented keys are the package identities.
// Key shapes across pnpm versions: "lodash@4.17.21", "/lodash@4.17.21",
// "/@scope/name@1.0.0", optionally with a "(peer)" suffix.
func parsePnpm(raw []byte) []Pkg {
	var out []Pkg
	curIdx := -1
	inPackages := false
	for _, ln := range strings.Split(string(raw), "\n") {
		if ln == "" {
			continue
		}
		// Top-level key (no indent) switches sections.
		if ln[0] != ' ' && ln[0] != '\t' {
			inPackages = strings.HasPrefix(ln, "packages:")
			curIdx = -1
			continue
		}
		if !inPackages {
			continue
		}
		// A package key is indented exactly two spaces and ends with ':'.
		if strings.HasPrefix(ln, "  ") && !strings.HasPrefix(ln, "   ") && strings.HasSuffix(strings.TrimRight(ln, " "), ":") {
			key := strings.TrimSpace(ln)
			key = strings.TrimSuffix(key, ":")
			key = strings.Trim(key, "'\"")
			if name, ver, ok := splitPnpmKey(key); ok {
				out = append(out, Pkg{Name: name, Version: ver})
				curIdx = len(out) - 1
			} else {
				curIdx = -1
			}
			continue
		}
		// Deeper lines belong to the current package; grab its integrity.
		if curIdx >= 0 {
			if i := strings.Index(ln, "integrity:"); i >= 0 {
				val := strings.TrimSpace(ln[i+len("integrity:"):])
				out[curIdx].Integrity = strings.Trim(val, " {}'\",")
			}
		}
	}
	return out
}

// splitPnpmKey turns a pnpm package key into (name, version). Strips a leading
// "/" and any "(peerDeps)" suffix, then splits on the '@' that precedes the
// version (the scope's leading '@' is ignored).
func splitPnpmKey(key string) (name, version string, ok bool) {
	if i := strings.IndexByte(key, '('); i >= 0 {
		key = key[:i] // drop peer-deps suffix
	}
	key = strings.TrimPrefix(key, "/")
	at := strings.LastIndex(key, "@")
	if at <= 0 { // no version separator, or starts with '@' only
		return "", "", false
	}
	name, version = key[:at], key[at+1:]
	if name == "" || version == "" || !(version[0] >= '0' && version[0] <= '9') {
		return "", "", false
	}
	return name, version, true
}

// parseYarn extracts installed packages from a yarn.lock (classic v1 format):
// a non-indented descriptor line (one or more comma-separated specifiers,
// ending ':') followed by indented `version`, `resolved`, `integrity` lines.
func parseYarn(raw []byte) []Pkg {
	var out []Pkg
	curIdx := -1
	for _, ln := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(ln) == "" || strings.HasPrefix(strings.TrimSpace(ln), "#") {
			continue
		}
		if ln[0] != ' ' && ln[0] != '\t' {
			// Descriptor line: take the first specifier, derive the name.
			desc := strings.TrimSuffix(strings.TrimSpace(ln), ":")
			first := strings.TrimSpace(strings.SplitN(desc, ",", 2)[0])
			first = strings.Trim(first, "\"")
			out = append(out, Pkg{Name: yarnName(first)})
			curIdx = len(out) - 1
			continue
		}
		if curIdx < 0 {
			continue
		}
		t := strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(t, "version"):
			out[curIdx].Version = strings.Trim(strings.TrimSpace(t[len("version"):]), "\"")
		case strings.HasPrefix(t, "resolved"):
			out[curIdx].Resolved = strings.Trim(strings.TrimSpace(t[len("resolved"):]), "\"")
		case strings.HasPrefix(t, "integrity"):
			out[curIdx].Integrity = strings.TrimSpace(t[len("integrity"):])
		}
	}
	return out
}

// yarnName extracts the package name from a yarn specifier like
// "lodash@^4.17.21" or "@scope/name@^1.0.0" — everything before the '@' that
// introduces the version range (the scope's leading '@' is not that one).
func yarnName(spec string) string {
	at := strings.LastIndex(spec, "@")
	if at <= 0 {
		return spec
	}
	return spec[:at]
}
