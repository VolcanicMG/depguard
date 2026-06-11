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

// ScanTarball scans a gzipped npm tarball stream and returns the same kind of
// Report a directory scan produces (capability + injection findings). npm
// tarballs prefix every entry with "package/"; that prefix is stripped so file
// classification matches an installed layout.
func ScanTarball(r io.Reader) (Report, error) {
	rep := Report{}
	gz, err := gzip.NewReader(r)
	if err != nil {
		return rep, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	seen := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return rep, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := strings.TrimPrefix(hdr.Name, "package/")
		if strings.Contains(name, "node_modules/") {
			continue // bundled deps get judged on their own
		}
		src, _ := io.ReadAll(io.LimitReader(tr, maxScanBytes))
		scanFile(name, src, &rep, seen)
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
