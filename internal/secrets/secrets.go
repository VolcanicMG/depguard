// Package secrets implements the commit/push gate that stops credential files
// (.env, key material, a secrets/ directory) from ever reaching the remote.
//
// Every other depguard layer guards against THIRD-PARTY code (a dependency that
// goes bad). This one guards against the repo's own authors leaking a secret:
// `guard check` hard-blocks a commit/push — same gate weight as a critical
// advisory — when a file matching a policy pattern is staged or already tracked
// by git (DESIGN.md §11). Untracked/gitignored files are skipped — git won't
// upload them, so they aren't a leak yet.
//
// The upload surface depends on the PHASE. At pre-commit it is the working
// tree's tracked + staged set (Find). At pre-push it is the OUTGOING COMMITS
// (FindOutgoing): a secret committed and then deleted in a later commit is gone
// from the index but still travels in the history the push transmits — and
// `git rm --cached` does not take it back out.
package secrets

import (
	"errors"
	"fmt"
	"os/exec"
	"path"
	"sort"
	"strings"
)

// Match is one flagged file paired with the pattern that caught it, so the
// report can tell the human WHY a path is blocked.
type Match struct {
	// Path is repo-relative with forward slashes (git's native form).
	Path string
	// Pattern is the secret-paths entry that matched.
	Pattern string
	// History marks a hit found in an OUTGOING COMMIT rather than the current
	// tree. Deleting the file now does not un-send it: the fix is a history
	// rewrite plus credential rotation, and the report must say so.
	History bool
}

// Find returns every git-tracked-or-staged file in dir that matches one of the
// patterns, sorted by path. It returns (nil, nil) when patterns is empty (gate
// off). When dir is not a git repo (or git is unavailable) it returns the git
// error so the caller can log-and-continue like the other fail-open checks —
// there is no upload surface to assert about, so the gate is simply inert.
func Find(dir string, patterns []string) ([]Match, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	files, err := gitFiles(dir)
	if err != nil {
		return nil, err
	}
	var out []Match
	for _, f := range files {
		if p, ok := matchAny(f, patterns); ok {
			out = append(out, Match{Path: f, Pattern: p})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// gitFiles is the union of already-tracked and currently-staged files, deduped —
// the CURRENT tree's upload surface. Note this is not everything a push
// transmits: a file removed in a later commit is absent here but still present
// in the outgoing history (see FindOutgoing).
func gitFiles(dir string) ([]string, error) {
	set := map[string]bool{}
	// Already tracked (in the index / committed): catches a secret that slipped
	// in before the gate existed and still rides every push until it is removed.
	// This is the workhorse — `ls-files` also lists a freshly `git add`ed file,
	// so it already covers most "staged" cases.
	tracked, err := gitLines(dir, "ls-files", "-z")
	if err != nil {
		return nil, err
	}
	for _, f := range tracked {
		set[f] = true
	}
	// Staged for THIS commit (Added/Copied/Modified/Renamed): belt-and-suspenders
	// for the pre-commit moment. Best-effort — ignore its error so a repo with no
	// HEAD yet (the very first commit) still gets the ls-files coverage above.
	if staged, err := gitLines(dir, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"); err == nil {
		for _, f := range staged {
			set[f] = true
		}
	}
	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	return out, nil
}

// FindOutgoing returns every file ADDED or MODIFIED by the commits a push would
// transmit, matched against the patterns. revArgs holds one git-log revision
// selector per pushed ref — "<remote-sha>..<local-sha>" for an existing remote
// branch, or {"<local-sha>", "--not", "--remotes"} for a brand-new one.
//
// This is the pre-push half of the gate: Find looks at the tree, this looks at
// the history, and only together do they cover what leaves the machine.
//
// It returns the matches it DID find alongside a joined error for every range it
// could not read. Swallowing those errors made a shallow clone — where the
// remote sha isn't present locally, so every range fails — report "no secrets"
// rather than "I could not look", which is the one answer a secret gate must
// never give. The caller decides what to do with it (cfg.Degrade).
func FindOutgoing(dir string, patterns []string, revArgs [][]string) ([]Match, error) {
	if len(patterns) == 0 || len(revArgs) == 0 {
		return nil, nil
	}
	seen := map[string]string{}
	var errs []error
	for _, rev := range revArgs {
		args := append([]string{"log", "--format=", "--name-only", "--diff-filter=ACMR", "-z"}, rev...)
		files, err := gitLines(dir, args...)
		if err != nil {
			errs = append(errs, fmt.Errorf("git log %s: %w", strings.Join(rev, " "), err))
			continue
		}
		for _, f := range files {
			if p, ok := matchAny(f, patterns); ok {
				seen[f] = p
			}
		}
	}
	var out []Match
	for f, p := range seen {
		out = append(out, Match{Path: f, Pattern: p, History: true})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, errors.Join(errs...)
}

// gitLines runs `git -C dir <args>` and splits NUL-delimited output (-z) into
// non-empty entries. NUL framing is used so paths with spaces or newlines (and
// git's quoting of them) can't corrupt the list.
func gitLines(dir string, args ...string) ([]string, error) {
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).Output()
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, p := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		if p != "" {
			lines = append(lines, p)
		}
	}
	return lines, nil
}

// matchAny reports whether repo-relative path file matches any pattern, and
// which one. Three tests per pattern (path uses forward slashes, so the stdlib
// `path` package — not `filepath` — is correct and OS-independent):
//   - trailing '/'  → directory: file equals or sits under that dir
//     ("secrets/" catches "secrets/prod.key")
//   - path.Match on the full path  (".env" → "./.env"; "config/*.pem")
//   - path.Match on the basename   ("*.pem" → any dir's *.pem; ".env" →
//     "config/.env"), since '*' in path.Match does not cross '/'.
func matchAny(file string, patterns []string) (string, bool) {
	base := path.Base(file)
	for _, p := range patterns {
		if strings.HasSuffix(p, "/") {
			d := strings.TrimSuffix(p, "/")
			if file == d || strings.HasPrefix(file, d+"/") {
				return p, true
			}
			continue
		}
		if ok, _ := path.Match(p, file); ok {
			return p, true
		}
		if ok, _ := path.Match(p, base); ok {
			return p, true
		}
	}
	return "", false
}
