package attestation

import (
	"crypto/sha512"
	"encoding/base64"
	"testing"
)

// The pinned PEM must parse into a usable root + intermediate at init.
func TestPinnedRootsParse(t *testing.T) {
	if rootPool == nil || interPool == nil {
		t.Fatal("pools are nil")
	}
	// A non-empty subject list is the cheapest proof the root parsed.
	if len(rootPool.Subjects()) == 0 { //nolint:staticcheck // Subjects() is fine for a test assertion
		t.Error("root pool is empty — pinned root failed to parse")
	}
}

// PAE encoding must match the DSSE spec's worked example exactly.
func TestPaeEncode(t *testing.T) {
	// DSSEv1 spec example: type "http://example.com/HelloWorld", body "hello world"
	got := string(paeEncode("http://example.com/HelloWorld", []byte("hello world")))
	want := "DSSEv1 29 http://example.com/HelloWorld 11 hello world"
	if got != want {
		t.Errorf("paeEncode =\n %q\nwant\n %q", got, want)
	}
}

func TestSriSha512Hex(t *testing.T) {
	sum := sha512.Sum512([]byte("the tarball"))
	sri := "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
	got, err := sriSha512Hex(sri)
	if err != nil {
		t.Fatal(err)
	}
	// hex of the same bytes
	const hexdigits = "0123456789abcdef"
	want := make([]byte, 0, len(sum)*2)
	for _, b := range sum {
		want = append(want, hexdigits[b>>4], hexdigits[b&0xf])
	}
	if got != string(want) {
		t.Errorf("sriSha512Hex mismatch")
	}
	if _, err := sriSha512Hex("sha256-abc"); err == nil {
		t.Error("non-sha512 SRI should error")
	}
}

func TestBindDigest(t *testing.T) {
	sum := sha512.Sum512([]byte("artifact"))
	hexd, _ := sriSha512Hex("sha512-" + base64.StdEncoding.EncodeToString(sum[:]))
	stmt := inTotoStatement{Subject: []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	}{{Name: "pkg", Digest: map[string]string{"sha512": hexd}}}}
	if err := bindDigest(stmt, "sha512-"+base64.StdEncoding.EncodeToString(sum[:])); err != nil {
		t.Errorf("matching digest should bind: %v", err)
	}
	// a mismatching subject digest must fail
	stmt.Subject[0].Digest["sha512"] = "deadbeef"
	if err := bindDigest(stmt, "sha512-"+base64.StdEncoding.EncodeToString(sum[:])); err == nil {
		t.Error("mismatched digest must not bind")
	}
}
