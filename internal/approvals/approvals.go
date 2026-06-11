// Package approvals persists the "ask once, remember" answers for packages
// that want to run lifecycle scripts (DESIGN.md §7).
//
// The file is committed with the repo so a decision travels to teammates and
// CI: an unvetted script can never silently run in a non-interactive context,
// but one a human explicitly vetted doesn't re-prompt everywhere.
package approvals

import (
	"encoding/json"
	"os"
	"time"
)

// Decision is the recorded outcome for one name@version.
type Decision string

const (
	// ApprovedBoxed: script may run inside the watched container (§8).
	ApprovedBoxed Decision = "approved-boxed"
	// ApprovedUncontained: human explicitly accepted running with no sandbox
	// (the §9 warn-approve path). The only decision that lets CI run bare.
	ApprovedUncontained Decision = "approved-uncontained"
	// Denied: never run this script; install proceeds without it.
	Denied Decision = "denied"
)

// Entry is one remembered answer.
type Entry struct {
	Decision Decision `json:"decision"`
	Date     string   `json:"date"`
	// Note is free-form context ("needs node-gyp build"), written by humans.
	Note string `json:"note,omitempty"`
}

// File is the on-disk .guard-approvals structure.
type File struct {
	Schema   int              `json:"schema"`
	Packages map[string]Entry `json:"packages"`
}

// FileName lives next to .guardrc, committed with the repo.
const FileName = ".guard-approvals"

// Load reads dir/.guard-approvals; a missing file is an empty (not error) state.
func Load(dir string) (*File, error) {
	f := &File{Schema: 1, Packages: map[string]Entry{}}
	data, err := os.ReadFile(dir + "/" + FileName)
	if err != nil {
		if os.IsNotExist(err) {
			return f, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, f); err != nil {
		return nil, err
	}
	if f.Packages == nil {
		f.Packages = map[string]Entry{}
	}
	return f, nil
}

// Get returns the remembered decision for name@version, if any.
func (f *File) Get(pkgAtVersion string) (Entry, bool) {
	e, ok := f.Packages[pkgAtVersion]
	return e, ok
}

// Set records a decision; call Save to persist.
func (f *File) Set(pkgAtVersion string, d Decision, note string) {
	f.Packages[pkgAtVersion] = Entry{
		Decision: d,
		Date:     time.Now().UTC().Format(time.RFC3339),
		Note:     note,
	}
}

// Save writes the file with stable formatting (indented JSON diffs cleanly
// in code review — these entries are security decisions, review them).
func (f *File) Save(dir string) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(dir+"/"+FileName, append(data, '\n'), 0o644)
}
