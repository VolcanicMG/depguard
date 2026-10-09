package waivers

import "testing"

// AdvisoryID is the one format `guard check` and the install proxy share; a
// drift here would make a waiver silently match one path and not the other.
func TestAdvisoryID(t *testing.T) {
	if got := AdvisoryID("@scope/pkg", "1.2.3", "GHSA-xxxx"); got != "advisory:@scope/pkg@1.2.3:GHSA-xxxx" {
		t.Errorf("AdvisoryID = %q", got)
	}
}
