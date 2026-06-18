package main

import (
	"strings"
	"testing"
)

func TestSetDepVersion(t *testing.T) {
	cases := []struct {
		name     string
		content  string
		dep      string
		version  string
		wantOK   bool
		wantHas  string // substring that must appear after the edit
		wantKeep string // substring that must SURVIVE untouched (other deps)
	}{
		{
			name:     "spaced",
			content:  `{"dependencies":{"react": "19.2.0","left-pad": "1.3.0"}}`,
			dep:      "react", version: "19.1.0", wantOK: true,
			wantHas:  `"react": "19.1.0"`,
			wantKeep: `"left-pad": "1.3.0"`,
		},
		{
			name:     "no spaces",
			content:  `{"dependencies":{"react":"19.2.0"}}`,
			dep:      "react", version: "19.1.0", wantOK: true,
			wantHas: `"react":"19.1.0"`,
		},
		{
			name:     "scoped name",
			content:  `{"dependencies":{"@scope/pkg": "2.0.0"}}`,
			dep:      "@scope/pkg", version: "1.9.0", wantOK: true,
			wantHas: `"@scope/pkg": "1.9.0"`,
		},
		{
			name:     "caret range overwritten to exact",
			content:  `{"dependencies":{"react": "^19.2.0"}}`,
			dep:      "react", version: "19.1.0", wantOK: true,
			wantHas: `"react": "19.1.0"`,
		},
		{
			name:    "absent dep is a no-op",
			content: `{"dependencies":{"react": "19.2.0"}}`,
			dep:     "vue", version: "3.0.0", wantOK: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := setDepVersion(c.content, c.dep, c.version)
			if ok != c.wantOK {
				t.Fatalf("setDepVersion ok = %v, want %v", ok, c.wantOK)
			}
			if !c.wantOK {
				if got != c.content {
					t.Fatalf("no-op edit changed content:\n%s", got)
				}
				return
			}
			if !strings.Contains(got, c.wantHas) {
				t.Fatalf("result missing %q:\n%s", c.wantHas, got)
			}
			if c.wantKeep != "" && !strings.Contains(got, c.wantKeep) {
				t.Fatalf("result dropped %q:\n%s", c.wantKeep, got)
			}
		})
	}
}
