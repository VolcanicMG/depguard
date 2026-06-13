// Package attestation verifies npm build-provenance attestations (Sigstore).
//
// What this adds over internal/provenance: that package verifies npm's registry
// ECDSA signature — proof the registry served what the PUBLISHER signed. This
// verifies the SLSA build provenance — proof the tarball was BUILT from a
// specific source repo by a specific CI workflow, the one link neither the
// integrity hash nor the registry signature establishes. npm serves these at
// <registry>/-/npm/v1/attestations/<name>@<version> as Sigstore bundles
// (a DSSE envelope wrapping an in-toto SLSA statement, signed by a short-lived
// Fulcio-issued certificate).
//
// Zero-dep, stdlib crypto only (the guard must not be attackable through its
// own supply chain). We verify, in order:
//
//  1. the DSSE signature over the in-toto payload, against the bundle's leaf cert
//  2. that the leaf cert chains to the PINNED Sigstore Fulcio root (below)
//  3. that the statement's subject digest equals the installed tarball's hash
//     (binds the attestation to the artifact we actually have)
//
// and then surface the attested source repo + builder identity.
//
// HONEST LIMITS (documented like internal/provenance's candor): this does NOT
// verify Rekor transparency-log inclusion, the signed certificate timestamp
// (SCT), or manage trust roots via TUF. A green result here means "a well-formed
// SLSA attestation, signed by a cert chaining to Fulcio, binds this exact
// tarball to the reported source" — a high bar, but not the full Sigstore
// guarantee. The pinned root is the production Fulcio GA root + intermediate
// (sha256 root fingerprint 3BA7B6CC…80C1); rotate them if Sigstore does.
package attestation

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Status is the verdict for one package's provenance attestation.
type Status string

const (
	// StatusNone: no attestation published for this version (common — most
	// packages aren't built with provenance yet). Not a failure.
	StatusNone Status = "none"
	// StatusVerified: signature + cert chain + digest binding all checked out.
	StatusVerified Status = "verified"
	// StatusInvalid: an attestation exists but failed verification — a tamper
	// signal the caller should treat as gating.
	StatusInvalid Status = "invalid"
)

// Result is the provenance outcome for one installed package.
type Result struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Status  Status `json:"status"`
	Source  string `json:"source,omitempty"`  // attested source repo, when verified
	Builder string `json:"builder,omitempty"` // attesting CI identity (cert SAN), when verified
	Reason  string `json:"reason,omitempty"`  // why it's invalid, when StatusInvalid
}

// pinnedRoots is the production Sigstore Fulcio root + intermediate, embedded so
// chain verification needs no network and can't be redirected. See the package
// doc for provenance + rotation note.
const pinnedRoots = `-----BEGIN CERTIFICATE-----
MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7
XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxex
X69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92j
YzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRY
wB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQ
KsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCM
WP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9
TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV7
7LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS
0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYB
BQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjp
KFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZI
zj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJR
nZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsP
mygUY7Ii2zbdCdliiow=
-----END CERTIFICATE-----`

// rootPool / interPool are built once from pinnedRoots: the self-signed root
// goes in roots, the intermediate in intermediates (so a bundle that ships only
// the leaf still chains).
var rootPool, interPool = buildPools()

func buildPools() (*x509.CertPool, *x509.CertPool) {
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	rest := []byte(pinnedRoots)
	for {
		var block []byte
		block, rest = nextPEM(rest)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block)
		if err != nil {
			continue
		}
		if c.Subject.CommonName == "sigstore-intermediate" {
			inters.AddCert(c)
		} else {
			roots.AddCert(c)
		}
	}
	return roots, inters
}

// nextPEM is a tiny zero-dep PEM scanner: returns the DER bytes of the next
// CERTIFICATE block and the remaining input. Avoids importing encoding/pem only
// to keep the surface minimal — but encoding/pem is stdlib, so this is purely
// stylistic and could be swapped. (Kept explicit for clarity.)
func nextPEM(in []byte) (der []byte, rest []byte) {
	const begin, end = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
	s := string(in)
	bi := strings.Index(s, begin)
	if bi < 0 {
		return nil, nil
	}
	ei := strings.Index(s[bi:], end)
	if ei < 0 {
		return nil, nil
	}
	body := s[bi+len(begin) : bi+ei]
	body = strings.ReplaceAll(body, "\n", "")
	body = strings.ReplaceAll(body, "\r", "")
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(body))
	if err != nil {
		return nil, nil
	}
	return b, in[bi+ei+len(end):]
}

// ── bundle / statement shapes ────────────────────────────────────────────────

type rawCert struct {
	RawBytes string `json:"rawBytes"` // base64 DER
}
type bundle struct {
	VerificationMaterial struct {
		Certificate          rawCert `json:"certificate"`
		X509CertificateChain struct {
			Certificates []rawCert `json:"certificates"`
		} `json:"x509CertificateChain"`
	} `json:"verificationMaterial"`
	DSSEEnvelope struct {
		Payload     string `json:"payload"`     // base64 in-toto statement
		PayloadType string `json:"payloadType"` // e.g. application/vnd.in-toto+json
		Signatures  []struct {
			Sig string `json:"sig"` // base64 ASN.1-DER ECDSA signature
		} `json:"signatures"`
	} `json:"dsseEnvelope"`
}
type attResponse struct {
	Attestations []struct {
		PredicateType string `json:"predicateType"`
		Bundle        bundle `json:"bundle"`
	} `json:"attestations"`
}

// inTotoStatement is the subset of the SLSA statement we read.
type inTotoStatement struct {
	Subject []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// Check fetches and verifies provenance for each package whose Integrity is
// known (the tarball hash we bind to). allowed packages are skipped (your own
// scopes). Network/parse failures fail OPEN per package (StatusNone with no
// error) so a registry blip never blocks a commit — the caller distinguishes
// StatusInvalid (a real tamper signal) from StatusNone. progress, if non-nil,
// is called once per package (incl. skips) with (done, total) for liveness on
// a large tree — one registry fetch per package makes this the slow check.
func Check(client *http.Client, registry string, pkgs []Pkg, allowed func(string) bool, progress func(done, total int)) []Result {
	reg := strings.TrimSuffix(registry, "/")
	var out []Result
	for i, p := range pkgs {
		if progress != nil {
			progress(i+1, len(pkgs))
		}
		if allowed != nil && allowed(p.Name) {
			continue
		}
		if p.Integrity == "" {
			continue // nothing to bind a subject digest to
		}
		out = append(out, verifyOne(client, reg, p))
	}
	return out
}

// Pkg is the minimal package identity Check needs (decoupled from lockfile.Pkg
// so this package imports nothing from the rest of the tree).
type Pkg struct {
	Name      string
	Version   string
	Integrity string // SRI "sha512-<base64>"
}

func verifyOne(client *http.Client, reg string, p Pkg) Result {
	r := Result{Name: p.Name, Version: p.Version, Status: StatusNone}
	url := reg + "/-/npm/v1/attestations/" + p.Name + "@" + p.Version
	resp, err := client.Get(url)
	if err != nil {
		return r // network failure → fail open (None)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return r // no attestation published
	}
	if resp.StatusCode != http.StatusOK {
		return r
	}
	var doc attResponse
	if json.NewDecoder(resp.Body).Decode(&doc) != nil || len(doc.Attestations) == 0 {
		return r
	}

	// Prefer the SLSA provenance attestation; fall back to the first one.
	att := doc.Attestations[0]
	for _, a := range doc.Attestations {
		if strings.Contains(a.PredicateType, "slsa.dev/provenance") {
			att = a
			break
		}
	}
	b := att.Bundle

	// 1. Parse the leaf certificate.
	leaf, chain, err := parseCerts(b)
	if err != nil {
		return invalid(r, "certificate: "+err.Error())
	}
	// 2. Verify the DSSE signature over the payload with the leaf's key.
	payload, err := base64.StdEncoding.DecodeString(b.DSSEEnvelope.Payload)
	if err != nil {
		return invalid(r, "payload not base64")
	}
	if len(b.DSSEEnvelope.Signatures) == 0 {
		return invalid(r, "no DSSE signature")
	}
	sig, err := base64.StdEncoding.DecodeString(b.DSSEEnvelope.Signatures[0].Sig)
	if err != nil {
		return invalid(r, "signature not base64")
	}
	if err := verifyDSSE(leaf, b.DSSEEnvelope.PayloadType, payload, sig); err != nil {
		return invalid(r, "DSSE signature: "+err.Error())
	}
	// 3. Verify the cert chains to the pinned Fulcio root.
	if err := verifyChain(leaf, chain); err != nil {
		return invalid(r, "cert chain: "+err.Error())
	}
	// 4. Bind the statement's subject digest to the installed tarball hash.
	var stmt inTotoStatement
	if json.Unmarshal(payload, &stmt) != nil {
		return invalid(r, "in-toto statement unparseable")
	}
	if err := bindDigest(stmt, p.Integrity); err != nil {
		return invalid(r, err.Error())
	}

	r.Status = StatusVerified
	r.Source = sourceRepo(stmt)
	r.Builder = builderIdentity(leaf)
	return r
}

func invalid(r Result, reason string) Result {
	r.Status, r.Reason = StatusInvalid, reason
	return r
}

// parseCerts returns the leaf cert and any intermediates from the bundle,
// supporting both the single-certificate and certificate-chain bundle shapes.
func parseCerts(b bundle) (leaf *x509.Certificate, chain []*x509.Certificate, err error) {
	var ders []string
	if b.VerificationMaterial.Certificate.RawBytes != "" {
		ders = append(ders, b.VerificationMaterial.Certificate.RawBytes)
	}
	for _, c := range b.VerificationMaterial.X509CertificateChain.Certificates {
		ders = append(ders, c.RawBytes)
	}
	if len(ders) == 0 {
		return nil, nil, fmt.Errorf("no certificate in bundle")
	}
	for i, d := range ders {
		raw, derr := base64.StdEncoding.DecodeString(d)
		if derr != nil {
			return nil, nil, fmt.Errorf("cert %d not base64", i)
		}
		c, cerr := x509.ParseCertificate(raw)
		if cerr != nil {
			return nil, nil, cerr
		}
		if i == 0 {
			leaf = c
		} else {
			chain = append(chain, c)
		}
	}
	return leaf, chain, nil
}

// verifyDSSE checks an ECDSA DSSE signature over the PAE-encoded payload. The
// hash follows the leaf key's curve (P-256→SHA-256, P-384→SHA-384).
func verifyDSSE(leaf *x509.Certificate, payloadType string, payload, sig []byte) error {
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("leaf key is not ECDSA")
	}
	pae := paeEncode(payloadType, payload)
	var digest []byte
	switch bits := pub.Curve.Params().BitSize; {
	case bits > 256:
		h := sha512.Sum384(pae)
		digest = h[:]
	default:
		h := sha256.Sum256(pae)
		digest = h[:]
	}
	if !ecdsa.VerifyASN1(pub, digest, sig) {
		return fmt.Errorf("does not verify")
	}
	return nil
}

// paeEncode builds the DSSE Pre-Authentication Encoding:
// "DSSEv1 " LEN(type) " " type " " LEN(body) " " body, lengths in ASCII decimal,
// body the RAW payload bytes.
func paeEncode(payloadType string, body []byte) []byte {
	var b strings.Builder
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(payloadType)))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(body)))
	b.WriteByte(' ')
	out := append([]byte(b.String()), body...)
	return out
}

// verifyChain checks the leaf chains to the pinned Fulcio root. Fulcio leaves
// are short-lived and long-expired by check time, so verification uses the
// leaf's own NotBefore as the current time (a documented limit: without Rekor
// we trust the cert's claimed validity window). Bundle-supplied intermediates
// augment the pinned intermediate pool.
func verifyChain(leaf *x509.Certificate, bundleChain []*x509.Certificate) error {
	inter := interPool.Clone()
	for _, c := range bundleChain {
		inter.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: inter,
		CurrentTime:   leaf.NotBefore,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageAny},
	})
	return err
}

// bindDigest confirms a subject in the statement carries the sha512 of the
// installed tarball — the step that ties the attestation to THIS artifact, not
// just some artifact. integrity is the SRI "sha512-<base64>".
func bindDigest(stmt inTotoStatement, integrity string) error {
	want, err := sriSha512Hex(integrity)
	if err != nil {
		return fmt.Errorf("tarball integrity: %w", err)
	}
	for _, s := range stmt.Subject {
		if strings.EqualFold(s.Digest["sha512"], want) {
			return nil
		}
	}
	return fmt.Errorf("attestation subject digest does not match installed tarball")
}

// sriSha512Hex turns "sha512-<base64>" into the lowercase hex digest.
func sriSha512Hex(integrity string) (string, error) {
	const p = "sha512-"
	if !strings.HasPrefix(integrity, p) {
		return "", fmt.Errorf("not a sha512 SRI")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(integrity[len(p):]))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// sourceRepo digs the source repository out of the SLSA predicate. It tolerates
// SLSA v1 (buildDefinition.externalParameters.workflow.repository) and v0.2
// (invocation.configSource.uri / materials[0].uri); returns "" if none found.
func sourceRepo(stmt inTotoStatement) string {
	var pred struct {
		BuildDefinition struct {
			ExternalParameters struct {
				Workflow struct {
					Repository string `json:"repository"`
				} `json:"workflow"`
			} `json:"externalParameters"`
		} `json:"buildDefinition"`
		Invocation struct {
			ConfigSource struct {
				URI string `json:"uri"`
			} `json:"configSource"`
		} `json:"invocation"`
		Materials []struct {
			URI string `json:"uri"`
		} `json:"materials"`
	}
	_ = json.Unmarshal(stmt.Predicate, &pred)
	if r := pred.BuildDefinition.ExternalParameters.Workflow.Repository; r != "" {
		return r
	}
	if r := pred.Invocation.ConfigSource.URI; r != "" {
		return r
	}
	if len(pred.Materials) > 0 {
		return pred.Materials[0].URI
	}
	return ""
}

// builderIdentity returns the CI identity that signed — the Fulcio cert's SAN
// URI (e.g. the GitHub Actions workflow ref). Empty if the cert has no URI SAN.
func builderIdentity(leaf *x509.Certificate) string {
	if len(leaf.URIs) > 0 {
		return leaf.URIs[0].String()
	}
	return ""
}
