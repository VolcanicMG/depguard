// Package provenance verifies npm's registry ECDSA signatures (DESIGN.md §6
// "tarball ≠ source / publish tampering"). npm's integrity hash proves the
// tarball matches the packument; it does NOT prove the registry served what
// the publisher signed. A compromised registry or account can serve a
// validly-hashed malicious version and pass every other check we have.
//
// npm publishes a signing keyring at /-/npm/v1/keys (ECDSA P-256 public keys
// in PKIX/SPKI DER, base64). Each version's dist.signatures carries an
// ECDSA-over-SHA256 signature of the message "<name>@<version>:<integrity>".
// We verify it with the Go standard library only — no external dependency,
// per the zero-dep invariant (a guard must not be attackable through its own
// supply chain).
package provenance

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Signature is one entry from a version's dist.signatures array.
type Signature struct {
	Keyid string `json:"keyid"`
	Sig   string `json:"sig"`
}

// Keyring is npm's registry signing keys, fetched once and reused.
type Keyring struct {
	keys map[string]*ecdsa.PublicKey // keyid → public key
}

// FetchKeyring downloads and parses the registry signing keys from
// <registry>/-/npm/v1/keys. Returns an error (caller fails OPEN) if the
// endpoint is unreachable or returns nothing usable.
func FetchKeyring(client *http.Client, registry string) (*Keyring, error) {
	url := strings.TrimSuffix(registry, "/") + "/-/npm/v1/keys"
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keys endpoint returned %d", resp.StatusCode)
	}
	var doc struct {
		Keys []struct {
			Keyid string `json:"keyid"`
			Key   string `json:"key"` // base64 PKIX/SPKI DER
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	kr := &Keyring{keys: map[string]*ecdsa.PublicKey{}}
	for _, k := range doc.Keys {
		der, err := base64.StdEncoding.DecodeString(k.Key)
		if err != nil {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			continue
		}
		if ec, ok := pub.(*ecdsa.PublicKey); ok {
			kr.keys[k.Keyid] = ec
		}
	}
	if len(kr.keys) == 0 {
		return nil, fmt.Errorf("no usable ECDSA keys in keyring")
	}
	return kr, nil
}

// Verify checks a version's registry signature against the message npm signs,
// "<name>@<version>:<integrity>". The three-way result distinguishes the cases
// the caller must treat differently:
//
//	signed=false           → no signature present (unsigned; warn, don't block)
//	signed=true,  ok=true  → a signature verified (trusted)
//	signed=true,  ok=false → signature present but INVALID (tamper; block)
func (kr *Keyring) Verify(name, version, integrity string, sigs []Signature) (ok, signed bool) {
	if len(sigs) == 0 || integrity == "" {
		return false, false
	}
	digest := sha256.Sum256([]byte(name + "@" + version + ":" + integrity))
	for _, s := range sigs {
		pub := kr.keys[s.Keyid]
		if pub == nil {
			continue // signed by a key we don't know — can't judge, skip
		}
		der, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			continue
		}
		if ecdsa.VerifyASN1(pub, digest[:], der) {
			return true, true
		}
	}
	return false, true // had signatures, none verified against a known key
}
