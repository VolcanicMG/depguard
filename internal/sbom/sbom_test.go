package sbom

import (
	"encoding/json"
	"testing"

	"depguard/internal/lockfile"
)

func TestPurlNpm(t *testing.T) {
	cases := map[string]string{
		"lodash@4.17.21":          "pkg:npm/lodash@4.17.21",
		"@angular/core@12.0.0":    "pkg:npm/%40angular/core@12.0.0",
		"@scope/a-b@1.2.3-beta.1": "pkg:npm/%40scope/a-b@1.2.3-beta.1",
	}
	for nameVer, want := range cases {
		// split last @ to feed (name, version)
		at := -1
		for i := len(nameVer) - 1; i >= 0; i-- {
			if nameVer[i] == '@' {
				at = i
				break
			}
		}
		if got := purlNpm(nameVer[:at], nameVer[at+1:]); got != want {
			t.Errorf("purlNpm(%q) = %q, want %q", nameVer, got, want)
		}
	}
}

func TestSriToHex(t *testing.T) {
	// sha512 of nothing-special: base64 "qg==" decodes to byte 0xaa.
	cdx, spdx, hexD, ok := sriToHex("sha512-qg==")
	if !ok || cdx != "SHA-512" || spdx != "SHA512" || hexD != "aa" {
		t.Errorf("got (%q,%q,%q,%v), want (SHA-512,SHA512,aa,true)", cdx, spdx, hexD, ok)
	}
	if _, _, _, ok := sriToHex(""); ok {
		t.Error("empty integrity should be ok=false")
	}
	if _, _, _, ok := sriToHex("md5-abc"); ok {
		t.Error("unsupported alg should be ok=false")
	}
}

var pkgs = []lockfile.Pkg{
	{Name: "lodash", Version: "4.17.21", Resolved: "https://reg/lodash.tgz", Integrity: "sha512-qg=="},
	{Name: "@scope/x", Version: "1.0.0"},
}

func TestCycloneDXValid(t *testing.T) {
	out, err := CycloneDX(Meta{Name: "proj", Version: "0.1.0", ToolVersion: "0.7.0"}, pkgs)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("CycloneDX output is not valid JSON: %v", err)
	}
	if doc["bomFormat"] != "CycloneDX" || doc["specVersion"] != "1.5" {
		t.Errorf("bad header: %v / %v", doc["bomFormat"], doc["specVersion"])
	}
	comps, _ := doc["components"].([]any)
	if len(comps) != 2 {
		t.Fatalf("want 2 components, got %d", len(comps))
	}
}

func TestSPDXValid(t *testing.T) {
	out, err := SPDX(Meta{Name: "proj", Version: "0.1.0", ToolVersion: "0.7.0"}, pkgs)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("SPDX output is not valid JSON: %v", err)
	}
	if doc["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("bad spdxVersion: %v", doc["spdxVersion"])
	}
	sp, _ := doc["packages"].([]any)
	if len(sp) != 2 {
		t.Fatalf("want 2 packages, got %d", len(sp))
	}
	// @scope/x has no resolved URL → must be NOASSERTION, not empty.
	p1, _ := sp[1].(map[string]any)
	if p1["downloadLocation"] != "NOASSERTION" {
		t.Errorf("missing resolved should map to NOASSERTION, got %v", p1["downloadLocation"])
	}
}
