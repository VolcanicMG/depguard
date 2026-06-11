// Package trace turns a raw strace log from the box into evidence — the
// dynamic half of DESIGN.md §8's observation chamber.
//
// The box runs install scripts under strace (network/execve/openat). Code
// can obfuscate itself past the static scanner, but it cannot hide the
// connect() it makes or the openat() on a key file: syscalls are where
// intent becomes observable fact.
//
// Verdict policy is deliberately conservative: only signals that have no
// legitimate build-time explanation drive UNSAFE (network reach-out, secret
// file access). Everything else is recorded as context, not conviction —
// false UNSAFEs would teach humans to ignore the tool.
package trace

import (
	"fmt"
	"regexp"
	"strings"
)

// Kind classifies one observed behavior.
type Kind string

const (
	// KindConnect: connect()/sendto() to a non-loopback address. With
	// --network none these fail — but the ATTEMPT is the evidence.
	KindConnect Kind = "network-attempt"
	// KindDNS: a hostname extracted from a DNS query payload — names the
	// destination even though no packet ever left the box.
	KindDNS Kind = "dns-query"
	// KindSecretPath: openat() on a path that holds credentials.
	KindSecretPath Kind = "secret-access"
	// KindExec: a spawned binary (context, not verdict).
	KindExec Kind = "exec"
)

// Observation is one piece of evidence from the trace.
type Observation struct {
	Kind   Kind
	Detail string
}

// Report is the parsed outcome of one boxed run.
type Report struct {
	Observations []Observation
	// Unsafe is true when behavior with no legitimate build-time
	// explanation was observed; the caller discards the script's output.
	Unsafe bool
}

// connectRe matches strace connect/sendto lines carrying an IPv4 or IPv6
// destination, tolerating the unfinished/resumed splits strace -f produces.
var connectRe = regexp.MustCompile(`sin6?_port=htons\((\d+)\).*?(?:inet_addr\("([^"]+)"\)|inet_pton\(AF_INET6, "([^"]+)")`)

// dnsLabelRe matches DNS wire-format hostnames inside strace's escaped
// payload dumps: length-prefixed labels print as \3www\4evil\3com.
var dnsLabelRe = regexp.MustCompile(`(?:\\\d{1,3}[A-Za-z0-9-]{1,63}){2,}`)

// openatRe captures the path argument of openat calls.
var openatRe = regexp.MustCompile(`openat\([^,]+, "([^"]+)"`)

// execveRe captures the binary of execve calls.
var execveRe = regexp.MustCompile(`execve\("([^"]+)"`)

// secretFragments are path pieces that mean credentials, not build inputs.
// Checked against openat paths; /home/node is the box's own scratch HOME
// (npm legitimately reads its .npmrc there), so it's exempted separately.
var secretFragments = []string{
	"/.ssh", "id_rsa", "id_ed25519", "/.aws", "/.docker/config", "/etc/shadow", ".npmrc",
}

// procEnvironRe flags reads of OTHER processes' environments. The script's
// own (/proc/self) is scrubbed anyway and some runtimes read it routinely.
var procEnvironRe = regexp.MustCompile(`/proc/\d+/environ`)

// Parse scans a raw strace log and produces the evidence report.
func Parse(log []byte) Report {
	var rep Report
	seen := map[string]bool{} // dedupe: one observation per distinct fact

	add := func(k Kind, detail string, unsafe bool) {
		key := string(k) + detail
		if seen[key] {
			return
		}
		seen[key] = true
		rep.Observations = append(rep.Observations, Observation{k, detail})
		if unsafe {
			rep.Unsafe = true
		}
	}

	for _, line := range strings.Split(string(log), "\n") {
		// Network destinations. Loopback is normal plumbing (and unroutable
		// out of the box anyway); everything else is reach-out intent —
		// EXCEPT port 53: that address is just the resolver from
		// resolv.conf, not where data was headed. For DNS, the queried NAME
		// is the evidence, decoded from the packet payload below.
		if m := connectRe.FindStringSubmatch(line); m != nil {
			addr := m[2]
			if addr == "" {
				addr = m[3]
			}
			if m[1] == "53" {
				for _, raw := range dnsLabelRe.FindAllString(line, -1) {
					if name := decodeDNSName(raw); name != "" {
						add(KindDNS, name, true)
					}
				}
			} else if !isLoopback(addr) && addr != "0.0.0.0" {
				add(KindConnect, fmt.Sprintf("%s:%s", addr, m[1]), true)
			}
			continue
		}
		if m := openatRe.FindStringSubmatch(line); m != nil {
			path := m[1]
			if isSecretPath(path) || procEnvironRe.MatchString(path) {
				add(KindSecretPath, path, true)
			}
			continue
		}
		if m := execveRe.FindStringSubmatch(line); m != nil {
			// Context only: tools don't convict, syscalls do. A curl exec
			// that matters will also produce a flagged connect().
			add(KindExec, m[1], false)
		}
	}
	return rep
}

// isSecretPath reports whether path touches credential locations. Paths
// inside the box's own mounts are exempt: the dep tree (/app), scratch HOME
// (/home/node — npm reads its .npmrc there on every run) and /tmp contain
// only data already inside the cage, so reading them proves nothing. The
// signal is reaching for paths that hold credentials on a REAL machine:
// /root/.ssh, /etc/shadow, another process's environ.
func isSecretPath(path string) bool {
	for _, mount := range []string{"/home/node/", "/app/", "/tmp/"} {
		if strings.HasPrefix(path, mount) {
			return false
		}
	}
	for _, frag := range secretFragments {
		if strings.Contains(path, frag) {
			return true
		}
	}
	return false
}

// isLoopback covers IPv4 127/8 and IPv6 ::1.
func isLoopback(addr string) bool {
	return strings.HasPrefix(addr, "127.") || addr == "::1"
}

// decodeDNSName converts strace's escaped wire format (\3www\4evil\3com)
// back into a dotted hostname. Returns "" for sequences that don't decode
// to something hostname-shaped.
func decodeDNSName(raw string) string {
	parts := regexp.MustCompile(`\\\d{1,3}`).Split(raw, -1)
	var labels []string
	for _, p := range parts {
		if p != "" {
			labels = append(labels, p)
		}
	}
	if len(labels) < 2 {
		return ""
	}
	return strings.Join(labels, ".")
}
