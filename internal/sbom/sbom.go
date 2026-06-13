// Package sbom renders the installed dependency set as a Software Bill of
// Materials. depguard already knows exactly what's installed (the lockfile is
// its source of truth, DESIGN.md §10); an SBOM is just that set in a portable,
// tool-consumable shape. Two formats are emitted from the same input:
// CycloneDX 1.5 JSON (the default — widest tooling support) and SPDX 2.3 JSON.
// Zero-dep: encoding/json + stdlib hex/base64 only, per the guard's own
// supply-chain invariant.
package sbom

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"depguard/internal/lockfile"
)

// Meta is the root project's identity, used as the SBOM's primary component.
type Meta struct {
	Name        string // project name (from package.json, or the dir name)
	Version     string // project version, may be ""
	ToolVersion string // guard's own version string, for the "creator" record
}

// purlNpm builds a Package URL for an npm component. Scoped names ("@scope/x")
// put the scope in the purl namespace with its leading '@' percent-encoded, per
// the purl spec (e.g. pkg:npm/%40angular/core@12.0.0). Unscoped names are
// pkg:npm/<name>@<version>.
func purlNpm(name, version string) string {
	if strings.HasPrefix(name, "@") {
		if slash := strings.IndexByte(name, '/'); slash > 0 {
			scope := "%40" + name[1:slash]
			return fmt.Sprintf("pkg:npm/%s/%s@%s", scope, name[slash+1:], version)
		}
	}
	return fmt.Sprintf("pkg:npm/%s@%s", name, version)
}

// sriToHex converts a Subresource-Integrity string ("sha512-<base64>") to a
// (cycloneDXAlg, spdxAlg, hexDigest) triple. Returns ok=false for an empty or
// unparseable value so callers simply omit the hash rather than emit a bad one.
func sriToHex(integrity string) (cdxAlg, spdxAlg, hexDigest string, ok bool) {
	dash := strings.IndexByte(integrity, '-')
	if dash <= 0 {
		return "", "", "", false
	}
	algo := strings.ToLower(integrity[:dash])
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(integrity[dash+1:]))
	if err != nil || len(raw) == 0 {
		return "", "", "", false
	}
	switch algo {
	case "sha512":
		return "SHA-512", "SHA512", hex.EncodeToString(raw), true
	case "sha256":
		return "SHA-256", "SHA256", hex.EncodeToString(raw), true
	case "sha1":
		return "SHA-1", "SHA1", hex.EncodeToString(raw), true
	default:
		return "", "", "", false
	}
}

// ── CycloneDX 1.5 ────────────────────────────────────────────────────────────

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}
type cdxComponent struct {
	Type    string    `json:"type"`
	Name    string    `json:"name"`
	Version string    `json:"version,omitempty"`
	Purl    string    `json:"purl,omitempty"`
	Hashes  []cdxHash `json:"hashes,omitempty"`
}
type cdxDoc struct {
	BomFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	Version     int    `json:"version"`
	Metadata    struct {
		Timestamp string `json:"timestamp"`
		Tools     []struct {
			Vendor  string `json:"vendor"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"tools"`
		Component cdxComponent `json:"component"`
	} `json:"metadata"`
	Components []cdxComponent `json:"components"`
}

// CycloneDX renders pkgs as a CycloneDX 1.5 JSON document.
func CycloneDX(meta Meta, pkgs []lockfile.Pkg) ([]byte, error) {
	var doc cdxDoc
	doc.BomFormat = "CycloneDX"
	doc.SpecVersion = "1.5"
	doc.Version = 1
	doc.Metadata.Timestamp = time.Now().UTC().Format(time.RFC3339)
	doc.Metadata.Tools = append(doc.Metadata.Tools, struct {
		Vendor  string `json:"vendor"`
		Name    string `json:"name"`
		Version string `json:"version"`
	}{"depguard", "guard", meta.ToolVersion})
	doc.Metadata.Component = cdxComponent{Type: "application", Name: meta.Name, Version: meta.Version}

	doc.Components = make([]cdxComponent, 0, len(pkgs))
	for _, p := range pkgs {
		c := cdxComponent{Type: "library", Name: p.Name, Version: p.Version, Purl: purlNpm(p.Name, p.Version)}
		if cdxAlg, _, hexD, ok := sriToHex(p.Integrity); ok {
			c.Hashes = []cdxHash{{Alg: cdxAlg, Content: hexD}}
		}
		doc.Components = append(doc.Components, c)
	}
	return json.MarshalIndent(doc, "", "  ")
}

// ── SPDX 2.3 ─────────────────────────────────────────────────────────────────

type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}
type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}
type spdxPackage struct {
	Name             string            `json:"name"`
	SPDXID           string            `json:"SPDXID"`
	VersionInfo      string            `json:"versionInfo,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
	Checksums        []spdxChecksum    `json:"checksums,omitempty"`
}
type spdxDoc struct {
	SPDXVersion       string `json:"spdxVersion"`
	DataLicense       string `json:"dataLicense"`
	SPDXID            string `json:"SPDXID"`
	Name              string `json:"name"`
	DocumentNamespace string `json:"documentNamespace"`
	CreationInfo      struct {
		Created  string   `json:"created"`
		Creators []string `json:"creators"`
	} `json:"creationInfo"`
	Packages []spdxPackage `json:"packages"`
}

// spdxID builds a valid SPDXRef identifier: SPDX allows only letters, digits,
// '.' and '-' in the idstring, so every other rune (notably '@' and '/' in
// scoped names) is replaced with '-'.
func spdxID(name, version string) string {
	repl := func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
			return r
		}
		return '-'
	}
	return "SPDXRef-Package-" + strings.Map(repl, name+"-"+version)
}

// SPDX renders pkgs as an SPDX 2.3 JSON document.
func SPDX(meta Meta, pkgs []lockfile.Pkg) ([]byte, error) {
	var doc spdxDoc
	doc.SPDXVersion = "SPDX-2.3"
	doc.DataLicense = "CC0-1.0"
	doc.SPDXID = "SPDXRef-DOCUMENT"
	doc.Name = meta.Name
	now := time.Now().UTC().Format(time.RFC3339)
	// A document namespace must be unique; the timestamp suffices for a local,
	// non-published SBOM and needs no network or UUID dependency.
	doc.DocumentNamespace = fmt.Sprintf("https://depguard/spdx/%s-%s", meta.Name, now)
	doc.CreationInfo.Created = now
	doc.CreationInfo.Creators = []string{"Tool: depguard-guard-" + meta.ToolVersion}

	doc.Packages = make([]spdxPackage, 0, len(pkgs))
	for _, p := range pkgs {
		dl := p.Resolved
		if dl == "" {
			dl = "NOASSERTION" // SPDX requires a value; NOASSERTION is the spec's "unknown"
		}
		sp := spdxPackage{
			Name:             p.Name,
			SPDXID:           spdxID(p.Name, p.Version),
			VersionInfo:      p.Version,
			DownloadLocation: dl,
			FilesAnalyzed:    false,
			ExternalRefs: []spdxExternalRef{{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  purlNpm(p.Name, p.Version),
			}},
		}
		if _, spdxAlg, hexD, ok := sriToHex(p.Integrity); ok {
			sp.Checksums = []spdxChecksum{{Algorithm: spdxAlg, ChecksumValue: hexD}}
		}
		doc.Packages = append(doc.Packages, sp)
	}
	return json.MarshalIndent(doc, "", "  ")
}
