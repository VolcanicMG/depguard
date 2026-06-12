package scanner

// Tarball scanning powers the capability DIFF (DESIGN.md §6): to tell what an
// update CHANGED, we scan a version we never installed — the previous one —
// straight from its published tarball and compare its capability surface to
// the version being approved. A package that was pure-JS last release and
// suddenly opens sockets this release is the classic "good package turned bad"
// signal, and it's the cheapest high-value check we can run.

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxArchiveBytes caps TOTAL decompressed bytes across the whole tarball. The
// per-file maxScanBytes bounds only the SCAN buffer, not the decompression work
// tar.Next() does to skip an entry's body: one entry declaring a huge body (a
// gzip bomb — ~10 MB of zeros expands to ~10 GB) is fully decompressed even
// though we scan just 1 MiB of it. Set far above any legitimate package's
// scanned surface so real scans are never truncated by this bound.
var maxArchiveBytes int64 = 256 << 20 // 256 MiB (var so a test can lower it)

// maxArchiveEntries caps the entry count — the other bomb shape (millions of
// tiny files) that the byte budget alone would not bound cheaply.
var maxArchiveEntries = 100000 // var so a test can lower it

// countingReader tallies bytes pulled from the underlying reader so the caller
// can tell a genuine EOF from "hit the decompression budget".
type countingReader struct {
	r io.Reader
	n int64
}

// Read passes through and accumulates the byte count. //nolint:wsl
func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// ScanTarball scans a gzipped npm tarball stream and returns the same kind of
// Report a directory scan produces (capability + injection findings). npm
// tarballs prefix every entry with "package/"; that prefix is stripped so file
// classification matches an installed layout. The stream is read under a total
// decompression budget so a malicious tarball cannot exhaust memory/CPU.
func ScanTarball(r io.Reader) (Report, error) {
	rep := Report{}
	gz, err := gzip.NewReader(r)
	if err != nil {
		return rep, err
	}
	defer gz.Close()
	// Count decompressed bytes pulled from gzip and hard-stop the tar reader at
	// the budget; a bomb surfaces as a finding, not as silent resource burn.
	counted := &countingReader{r: gz}
	tr := tar.NewReader(io.LimitReader(counted, maxArchiveBytes))
	seen := map[string]bool{}
	entries := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Hitting the byte budget truncates the stream, which surfaces here
			// as a read error. Treat THAT as a bomb signal; a genuine parse
			// error on a normal-sized archive still propagates.
			if counted.n >= maxArchiveBytes {
				rep.Findings = append(rep.Findings, Finding{
					Severity: Danger,
					What:     "tarball exceeds decompression budget (possible zip bomb)",
				})
				return rep, nil
			}
			return rep, err
		}
		entries++
		if entries > maxArchiveEntries {
			rep.Findings = append(rep.Findings, Finding{
				Severity: Danger,
				What:     "tarball has an abnormal number of entries (possible zip bomb)",
			})
			return rep, nil
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := strings.TrimPrefix(hdr.Name, "package/")
		if strings.Contains(name, "node_modules/") {
			continue // bundled deps get judged on their own
		}
		// Stream the entry IN FULL through the shared sweep. The whole tar
		// stream is already under maxArchiveBytes (via counted), and scanReader
		// applies the per-file ceiling, so this stays bounded.
		scanFileStream(name, tr, &rep, seen)
	}
	return rep, nil
}

// FetchReport downloads a specific version's tarball from the registry and
// scans it. The tarball URL follows npm's fixed convention:
// <registry>/<name>/-/<unscoped-name>-<version>.tgz.
func FetchReport(client *http.Client, registry, name, version string) (Report, error) {
	unscoped := name
	if i := strings.LastIndex(unscoped, "/"); i >= 0 {
		unscoped = unscoped[i+1:]
	}
	url := fmt.Sprintf("%s/%s/-/%s-%s.tgz", strings.TrimSuffix(registry, "/"), name, unscoped, version)
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Get(url)
	if err != nil {
		return Report{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Report{}, fmt.Errorf("tarball fetch returned %d", resp.StatusCode)
	}
	return ScanTarball(resp.Body)
}

// DiffNew returns the findings present in curr but NOT in prev — i.e. the
// capabilities/signals an update newly introduced. Keyed on What, so "opens
// network connections" appearing for the first time this version surfaces;
// signals the previous version already had are not re-flagged.
func DiffNew(prev, curr Report) []Finding {
	had := map[string]bool{}
	for _, f := range prev.Findings {
		had[f.What] = true
	}
	var added []Finding
	for _, f := range curr.Findings {
		if !had[f.What] {
			added = append(added, f)
		}
	}
	return added
}
