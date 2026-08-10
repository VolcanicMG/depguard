package attestation

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// bindStatement is verification steps 4-5 — the whole gating decision. A valid
// Fulcio signature is not enough: the signer must belong to the repo the
// statement claims, or any Sigstore identity could self-attest someone else's
// provenance. Non-GitHub sources are NOT tamper — they fail open as NONE.
func TestBindStatement(t *testing.T) {
	const san = "https://github.com/acme/widget/.github/workflows/publish.yml@refs/heads/main"
	sum := sha512.Sum512([]byte("artifact"))
	sri := "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
	hexd, _ := sriSha512Hex(sri)
	stmt := func(source string) inTotoStatement {
		return inTotoStatement{
			Subject: []struct {
				Name   string            `json:"name"`
				Digest map[string]string `json:"digest"`
			}{{Name: "pkg", Digest: map[string]string{"sha512": hexd}}},
			Predicate: json.RawMessage(`{"buildDefinition":{"externalParameters":{"workflow":{"repository":"` + source + `"}}}}`),
		}
	}
	cases := []struct {
		name, source, identity string
		want                   Status
	}{
		{"digest + identity bind", "https://github.com/acme/widget", san, StatusVerified},
		{"identity names another repo", "https://github.com/acme/other", san, StatusInvalid},
		{"identity names another owner", "https://github.com/evil/widget", san, StatusInvalid},
		{"cert carries no identity", "https://github.com/acme/widget", "", StatusInvalid},
		{"host-spoofed SAN", "https://github.com/acme/widget",
			"https://evil.example/github.com/acme/widget/x.yml", StatusInvalid},
		// Not a tamper signal: npm carries GitLab-built provenance too, and
		// calling it INVALID would block a commit on a false accusation.
		{"unsupported forge fails open", "https://gitlab.com/acme/widget", san, StatusNone},
		{"no source claimed fails open", "", san, StatusNone},
	}
	for _, c := range cases {
		got, reason := bindStatement(stmt(c.source), sri, c.identity)
		if got != c.want {
			t.Errorf("%s: status = %q (%s), want %q", c.name, got, reason, c.want)
		}
		if got != StatusVerified && reason == "" {
			t.Errorf("%s: non-verified status carries no reason", c.name)
		}
	}
	// A digest mismatch still outranks everything — that is the tamper case.
	if got, _ := bindStatement(stmt("https://github.com/acme/widget"), "sha512-"+base64.StdEncoding.EncodeToString(sha512.New().Sum(nil)), san); got != StatusInvalid {
		t.Errorf("digest mismatch status = %q, want %q", got, StatusInvalid)
	}
}

// githubRepoPath is the whole identity matcher, so its rejections are security
// boundaries: the host must come from a real URL parse, never a substring —
// otherwise any forge can put "github.com/<victim>" in a path and bind.
func TestGithubRepoPath(t *testing.T) {
	cases := map[string]string{
		// accepted shapes (SLSA sources and Fulcio SANs)
		"https://github.com/acme/widget":                      "acme/widget",
		"https://github.com/acme/widget.git":                  "acme/widget",
		"git+https://github.com/acme/widget.git@refs/tags/v1": "acme/widget",
		"https://github.com/ACME/Widget":                      "acme/widget",
		"acme/widget":                                         "acme/widget",
		"github.com/acme/widget":                              "acme/widget",
		"https://github.com/acme/widget/.github/workflows/publish.yml@refs/heads/main": "acme/widget",
		// rejected: substring "github.com/" on somebody else's host
		"https://gitlab.com/github.com/expressjs/express//.gitlab-ci.yml@refs/heads/main": "",
		"https://evil.com/github.com/expressjs/express/x.yml":                             "",
		"https://gitea.evil.io/a/b?x=github.com/expressjs/express":                        "",
		"https://github.com.evil.io/expressjs/express":                                    "",
		// rejected: not a repo / other forge / unparseable
		"https://github.com/acme":         "",
		"https://example.com/acme/widget": "",
		"":                                "",
		// rejected: schemes Fulcio/SLSA never emit
		"javascript://github.com/acme/widget": "",
		"http://github.com/acme/widget":       "",
	}
	for in, want := range cases {
		if got := githubRepoPath(in); got != want {
			t.Errorf("githubRepoPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// A fetch/parse that couldn't COMPLETE is StatusDegraded (fail-open, visible),
// distinct from a clean "no attestation published" (StatusNone) — so a transient
// or hostile failure isn't silently read as absence.
func TestVerifyOneDegradedVsNone(t *testing.T) {
	p := Pkg{Name: "x", Version: "1.0.0", Integrity: "sha512-abc"}

	handlers := []struct {
		name string
		fn   http.HandlerFunc
		want Status
	}{
		{"clean 404", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }, StatusNone},
		{"200 empty list", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"attestations":[]}`) }, StatusNone},
		{"HTTP 500", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) }, StatusDegraded},
		{"unparseable body", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "{not json") }, StatusDegraded},
	}
	for _, h := range handlers {
		srv := httptest.NewServer(h.fn)
		got := verifyOne(srv.Client(), srv.URL, p)
		srv.Close()
		if got.Status != h.want {
			t.Errorf("%s: status = %q, want %q", h.name, got.Status, h.want)
		}
		if h.want == StatusDegraded && got.Reason == "" {
			t.Errorf("%s: degraded result carries no reason", h.name)
		}
	}

	// A network error (server already closed) is degraded, not none.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := dead.URL
	dead.Close()
	if got := verifyOne(http.DefaultClient, url, p); got.Status != StatusDegraded || got.Reason == "" {
		t.Errorf("network error: status = %q reason %q, want degraded + reason", got.Status, got.Reason)
	}
}
