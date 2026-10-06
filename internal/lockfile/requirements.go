package lockfile

// requirements.txt (pip) parser for the check path. Only exact registry pins
// (`name==version`, optionally `--hash=`-locked) become packages; everything
// else that names a dependency source is counted as skipped so the caller can
// report a partially-understood file instead of a quietly smaller one.

import (
	"errors"
	"regexp"
	"strings"
)

var (
	// pip's comment rule: '#' at line start or after whitespace.
	reqComment = regexp.MustCompile(`(^|\s)#.*$`)
	// name[extras]==version / ===version — the only shape that pins one release.
	reqPinned = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*===?\s*([A-Za-z0-9.+!_-]+)$`)
	// The first whitespace-preceded option ends the requirement part.
	reqOptStart = regexp.MustCompile(`\s-`)
	reqHash     = regexp.MustCompile(`^(sha256|sha384|sha512):[0-9a-fA-F]+$`)
	reqNameSep  = regexp.MustCompile(`[-_.]+`)
)

// reqSourceOpts are option lines that name a dependency source guard does not
// follow or cannot pin-check in phase 1 — counted as skipped, never dropped.
// ponytail: -r/-c includes are not followed; read the included file later.
var reqSourceOpts = map[string]bool{
	"-r": true, "--requirement": true, "-c": true, "--constraint": true,
	"-e": true, "--editable": true, "-f": true, "--find-links": true,
}

// normalizePyName is PEP 503 normalization: lowercase, runs of -_. → "-".
func normalizePyName(n string) string {
	return reqNameSep.ReplaceAllString(strings.ToLower(n), "-")
}

// parseRequirements extracts exact pins from a requirements.txt. Each pinned
// line yields a Pkg (FromRegistry, Ecosystem "pypi", Integrity = its --hash
// values space-joined in file order). Unpinned specifiers, editables, paths,
// VCS/direct URLs and -r/-c/-f lines count as skipped; pure option lines
// (--index-url, --pre, ...) are ignored. Content that yields neither is an
// error, mirroring altlock: an unparsed file must not look empty.
func parseRequirements(raw []byte) ([]Pkg, int, error) {
	// Join backslash continuations before anything else, as pip does.
	text := strings.ReplaceAll(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\\\n", " ")
	var out []Pkg
	skipped, content := 0, 0
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(reqComment.ReplaceAllString(ln, ""))
		if ln == "" {
			continue
		}
		content++
		if strings.HasPrefix(ln, "-") {
			opt := strings.Fields(ln)[0]
			if i := strings.IndexByte(opt, '='); i > 0 {
				opt = opt[:i]
			}
			if !strings.HasPrefix(opt, "--") && len(opt) > 2 {
				opt = opt[:2] // -rfile.txt
			}
			if reqSourceOpts[opt] {
				skipped++
			}
			continue
		}
		spec, opts := ln, ""
		if loc := reqOptStart.FindStringIndex(ln); loc != nil {
			spec, opts = ln[:loc[0]], ln[loc[0]:]
		}
		if i := strings.IndexByte(spec, ';'); i >= 0 {
			spec = spec[:i] // environment marker
		}
		m := reqPinned.FindStringSubmatch(strings.TrimSpace(spec))
		hashes, ok := reqHashes(opts)
		if m == nil || !ok {
			skipped++
			continue
		}
		out = append(out, Pkg{
			Name:         normalizePyName(m[1]),
			Version:      strings.ToLower(strings.TrimSpace(m[3])),
			Integrity:    strings.Join(hashes, " "),
			FromRegistry: true,
			Ecosystem:    "pypi",
		})
	}
	if content > 0 && len(out) == 0 && skipped == 0 {
		return nil, 0, errors.New("requirements.txt: no entries recognized")
	}
	return out, skipped, nil
}

// reqHashes collects --hash values from a requirement's trailing options
// (`--hash=alg:hex` or `--hash alg:hex`). ok=false on a malformed hash, so the
// line is reported as not understood rather than checked against a bad pin.
func reqHashes(opts string) (hashes []string, ok bool) {
	f := strings.Fields(opts)
	for i := 0; i < len(f); i++ {
		v, isHash := strings.CutPrefix(f[i], "--hash=")
		if !isHash && f[i] == "--hash" && i+1 < len(f) {
			i++
			v, isHash = f[i], true
		}
		if !isHash {
			continue // other per-requirement options don't change the pin
		}
		if !reqHash.MatchString(v) {
			return nil, false
		}
		hashes = append(hashes, v)
	}
	return hashes, true
}
