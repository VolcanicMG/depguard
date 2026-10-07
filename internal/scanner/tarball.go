package scanner

// Tarball scanning powers the capability DIFF (DESIGN.md §6): to tell what an
// update CHANGED, we scan a version we never installed — the previous one —
// straight from its published tarball and compare its capability surface to
// the version being approved. A package that was pure-JS last release and
// suddenly opens sockets this release is the classic "good package turned bad"
// signal, and it's the cheapest high-value check we can run.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"depguard/internal/sdist"
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
	return scanTar(r, func(name string) (string, bool) {
		name = strings.TrimPrefix(name, "package/")
		// Bundled deps get judged on their own.
		return name, !strings.Contains(name, "node_modules/")
	})
}

// ScanSdist scans a Python source distribution (.tar.gz) the same way: every
// file through the shared sweeps (Python code gets the Python patterns), with the
// "<name>-<version>/" root stripped. Report.Scripts carries the build facts a
// reviewer approves — the backend, its requirements, a setup.py — since an sdist
// runs that code at build time. A pyproject.toml guard can't read is a finding.
func ScanSdist(tgz []byte) (Report, error) {
	rep, err := scanTar(bytes.NewReader(tgz), func(name string) (string, bool) {
		_, rel, ok := strings.Cut(strings.TrimPrefix(name, "./"), "/")
		return rel, ok && rel != ""
	})
	if err != nil {
		return rep, err
	}
	b, berr := sdist.BuildRequires(tgz)
	if berr != nil {
		rep.Findings = append(rep.Findings, Finding{Severity: Danger, What: "unreadable [build-system] table: " + berr.Error(), Where: "pyproject.toml"})
	}
	rep.Scripts = buildFacts(b)
	return rep, nil
}

// buildFacts renders an sdist's build setup as the prompt's "scripts" lines.
func buildFacts(b sdist.Build) map[string]string {
	facts := map[string]string{}
	switch {
	case b.Backend != "" && b.InTree:
		facts["build backend"] = b.Backend + " (in-tree)"
	case b.Backend != "":
		facts["build backend"] = b.Backend
	default:
		facts["build backend"] = "setuptools (legacy setup.py)"
	}
	facts["build requires"] = "(none)"
	if len(b.Requires) > 0 {
		facts["build requires"] = strings.Join(b.Requires, ", ")
	}
	if b.SetupPy {
		facts["setup.py"] = "present (runs at build time)"
	}
	return facts
}

// scanTar walks a gzipped tar under the decompression budget, mapping each
// entry name through rel (which may also skip it) before the shared sweep.
func scanTar(r io.Reader, rel func(string) (string, bool)) (Report, error) {
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
		name, ok := rel(hdr.Name)
		if !ok {
			continue
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
