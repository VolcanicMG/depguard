// Package scanner is the static half of the script check (DESIGN.md §6).
//
// It inspects an installed package directory for the signals a human needs
// when deciding whether to approve a lifecycle script: which scripts exist,
// what capabilities the code touches (network, fs, child_process, env), and
// obfuscation tells (eval, long base64 blobs). It produces findings, not a
// verdict — "clean" cannot be proven, so the output feeds an informed y/N
// and the dynamic watch in the box does the rest.
package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Severity buckets findings for display ordering.
type Severity int

const (
	Info Severity = iota
	Warn
	Danger
)

// String renders the severity tag shown in the approval prompt.
func (s Severity) String() string {
	switch s {
	case Danger:
		return "DANGER"
	case Warn:
		return "warn"
	default:
		return "info"
	}
}

// MarshalJSON emits the severity as its string label so --json/MCP output is
// readable ("DANGER") rather than an opaque enum int.
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// Finding is one observed signal in a package's code.
type Finding struct {
	Severity Severity
	// What is the human-readable signal ("spawns child processes").
	What string
	// Where is file:line for the first occurrence, "" for package-level facts.
	Where string
}

// Report is the scan result for one package directory.
type Report struct {
	// Scripts maps lifecycle phase → command for install-relevant scripts.
	Scripts  map[string]string
	Findings []Finding
}

// HasInstallScripts reports whether the package declares any script npm would
// auto-run at install time — the #1 supply-chain attack vector.
func (r Report) HasInstallScripts() bool { return len(r.Scripts) > 0 }

// installPhases are the lifecycle events npm runs automatically when
// installing a REGISTRY dependency. `prepare` is deliberately absent: npm
// only runs it for git deps and the root project, and flagging it here
// caused approval prompts for packages (husky users, half the ecosystem)
// whose prepare script would never have executed.
var installPhases = []string{"preinstall", "install", "postinstall"}

// capabilityPatterns map a regex over JS source to the capability it implies.
// Compiled once; order here is display order in the prompt.
var capabilityPatterns = []struct {
	re   *regexp.Regexp
	what string
	sev  Severity
}{
	// Network reach: how stolen data leaves the machine.
	{regexp.MustCompile(`require\(['"](https?|net|dgram|tls)['"]\)|from ['"](https?|net|dgram|tls)['"]|fetch\s*\(`), "opens network connections", Warn},
	// Process spawning: "curl | bash" lives here.
	{regexp.MustCompile(`require\(['"]child_process['"]\)|from ['"]child_process['"]|execSync|spawnSync`), "spawns child processes", Warn},
	// Secret-bearing locations.
	{regexp.MustCompile(`\.ssh|id_rsa|\.npmrc|\.aws|\.docker/config`), "references secret file paths (~/.ssh, .npmrc, .aws)", Danger},
	// Crypto-wallet / clipboard theft — the payload of most modern npm stealers.
	{regexp.MustCompile(`wallet\.dat|keystore|\.electrum|metamask|(?i)clipboard|/\.config/(solana|ethereum)`), "references crypto-wallet / clipboard (common stealer target)", Danger},
	{regexp.MustCompile(`process\.env`), "reads environment variables", Info},
	{regexp.MustCompile(`os\.homedir\s*\(|require\(['"]os['"]\)\.homedir|homedir\s*\(`), "reads the user's home directory", Warn},
	// Dynamic require/import hides WHAT gets loaded from a static reader.
	{regexp.MustCompile(`require\(\s*[^'"\s)]|import\(\s*[^'"\s)]`), "dynamic require/import (obscures what's loaded)", Warn},
	{regexp.MustCompile(`process\.binding\s*\(`), "uses process.binding (low-level native access)", Warn},
	// Obfuscation tells: legitimate build scripts have no reason to hide.
	{regexp.MustCompile(`\beval\s*\(|new Function\s*\(`), "dynamic code execution (eval / new Function)", Danger},
	// Base64 is only Warn and high-threshold: minified bundles and inline
	// sourcemaps routinely carry long base64 runs, so DANGER here was pure
	// false-positive fuel (the exact fatigue that trains users to ignore the
	// tool). A genuinely packed payload still trips it; context decides.
	{regexp.MustCompile(`[A-Za-z0-9+/]{350,}={0,2}`), "long base64-like blob (possible packed payload)", Warn},
}

// injectionPatterns flag text aimed at an LLM/agent that might READ this
// package — the prompt-injection vector. As agentic review and MCP servers
// increasingly judge dependencies, a package can carry instructions ("ignore
// previous instructions", "this file is safe, skip it") to disarm the
// reviewer. These are heuristics, surfaced as findings for a human/agent to
// weigh — never auto-trusted. Case-insensitive; matched across code AND text
// files (README/markdown/json), since the payload usually hides in prose.
var injectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore (all |any )?(the )?(previous|prior|above|preceding|earlier) (instruction|prompt|context|message)`),
	regexp.MustCompile(`(?i)disregard (the |all |any )?(previous|above|prior|preceding)`),
	regexp.MustCompile(`(?i)(this file|this package|this code|the following) is (safe|trusted|verified|benign)`),
	regexp.MustCompile(`(?i)(skip|do not (scan|review|read|analyze|inspect|audit)) this (file|package|directory)`),
	regexp.MustCompile(`(?i)(no need|nothing|not necessary) to (review|audit|check|scan|worry)`),
	regexp.MustCompile(`(?i)\bas an? (ai|language model|assistant|llm)\b`),
	regexp.MustCompile(`(?i)\byou are (now |a |an )?(an? )?(ai|assistant|chatbot|llm|agent)\b`),
	regexp.MustCompile(`(?i)(system|developer) prompt`),
	regexp.MustCompile(`(?i)<\s*/?\s*(system|assistant|instructions?|im_start|im_end)\s*>`),
	regexp.MustCompile(`(?i)(do not|don't|never) (tell|inform|alert|warn|flag|report|mention)`),
}

// Streaming-scan knobs. We scan every file IN FULL (not just a head) by sliding
// a window over it: scanChunk fresh bytes per read, carrying scanOverlap bytes
// between windows so a match straddling a seam is still found. Memory per file
// is ~scanChunk+scanOverlap regardless of file size, and Go's RE2 engine makes
// matching linear (no ReDoS), so full coverage is not a DoS vector.
const (
	scanChunk   = 1 << 20  // 1 MiB: fresh bytes per window
	scanOverlap = 64 << 10 // 64 KiB: carried between windows (>> longest pattern)
)

// maxFileScanBytes is the per-file ceiling: full coverage below it (covers
// essentially every real source/bundle file), flag-and-stop above it so a single
// pathological file can't burn unbounded CPU. The tarball path is additionally
// bounded by maxArchiveBytes. var (not const) so a test can lower it cheaply.
var maxFileScanBytes int64 = 64 << 20 // 64 MiB

// ReadScripts returns just the install-phase scripts from a package dir —
// the cheap check (one small file read) that decides whether the expensive
// full-tree capability sweep is needed at all. ~90% of packages have no
// install scripts and exit here.
func ReadScripts(dir string) (map[string]string, error) {
	pkgRaw, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return nil, fmt.Errorf("read package.json: %w", err)
	}
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(pkgRaw, &pkg); err != nil {
		return nil, fmt.Errorf("parse package.json: %w", err)
	}
	scripts := map[string]string{}
	for _, phase := range installPhases {
		if cmd, ok := pkg.Scripts[phase]; ok {
			scripts[phase] = cmd
		}
	}
	return scripts, nil
}

// ScanDir statically scans one installed package directory
// (node_modules/<name>) and returns its report.
func ScanDir(dir string) (Report, error) {
	rep := Report{}

	// 1. Lifecycle scripts from package.json — the facts npm acts on.
	scripts, err := ReadScripts(dir)
	if err != nil {
		return rep, err
	}
	rep.Scripts = scripts

	// 2. Content sweep. Code files (.js/.ts/...) get the capability patterns;
	// code AND text files (README/markdown/json) get the prompt-injection and
	// invisible-Unicode checks, since injection payloads hide in prose. First
	// hit per distinct signal only — the prompt needs "this package opens
	// sockets", not 400 line numbers.
	seen := map[string]bool{}
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			// Skip nested node_modules: those deps get their own scan.
			if d.Name() == "node_modules" && path != dir {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		f, oerr := os.Open(path)
		if oerr != nil {
			return nil // unreadable file: skip, don't fail the whole scan
		}
		scanFileStream(rel, f, &rep, seen)
		_ = f.Close()
		return nil
	})
	return rep, err
}

// scanFile applies every sweep to one file's bytes: the prebuilt-binary flag,
// the capability patterns (code only), and the injection/Unicode checks (code
// and text). Shared by the directory scan and the tarball scan so both judge a
// file identically. seen dedupes each distinct signal across the package.
func scanFileStream(rel string, r io.Reader, rep *Report, seen map[string]bool) {
	// Prebuilt binaries ship as opaque bytes — we can't scan a .node addon or a
	// bundled executable as source, so the most we can do is flag that one is
	// present (a native addon or, worse, a stowaway binary). Checked on name
	// alone, so it works even when we never read the (binary) content.
	const binWhat = "ships a prebuilt binary (opaque to source scanning)"
	if binaryExts[filepath.Ext(rel)] && !seen[binWhat] {
		seen[binWhat] = true
		rep.Findings = append(rep.Findings, Finding{Severity: Warn, What: binWhat, Where: rel})
	}
	code, text := isCodeFile(rel), isTextFile(rel)
	if !code && !text {
		return // not scanned as source; the caller need not have read r
	}
	scanReader(rel, r, code, rep, seen)
}

// scanReader streams r through the capability + injection sweeps with bounded
// memory, scanning the file IN FULL rather than only its head. It reads in
// scanChunk windows, prepending scanOverlap bytes of the previous window so a
// match across a seam is still caught; lineBase keeps Where line numbers exact
// across windows. A file past maxFileScanBytes is scanned to the ceiling and
// flagged (so a pathological input can't run matching unbounded).
func scanReader(rel string, r io.Reader, code bool, rep *Report, seen map[string]bool) {
	var (
		carry    []byte // tail of the previous window, re-scanned with the next
		lineBase int    // newlines before carry[0]; line of carry[0] == lineBase+1
		total    int64  // bytes pulled from r so far
		buf      = make([]byte, scanChunk)
	)
	for {
		n, err := io.ReadFull(r, buf)
		if n > 0 {
			total += int64(n)
			// Build an independent window = carry + fresh, so appending fresh
			// bytes can never clobber the carry backing array.
			window := make([]byte, 0, len(carry)+n)
			window = append(window, carry...)
			window = append(window, buf[:n]...)

			if code {
				scanPatterns(rel, window, capabilityFinders, rep, seen, lineBase)
			}
			scanInjection(rel, window, code, rep, seen, lineBase)

			// Carry the last scanOverlap bytes forward. Back the cut up to a
			// UTF-8 rune boundary so the next window's rune decode (bidi /
			// zero-width) sees whole runes, never a half rune split at the seam.
			keep := scanOverlap
			if keep > len(window) {
				keep = len(window)
			}
			cut := len(window) - keep
			for cut > 0 && !utf8.RuneStart(window[cut]) {
				cut--
			}
			lineBase += bytes.Count(window[:cut], []byte{'\n'})
			carry = append([]byte(nil), window[cut:]...)
		}
		if err != nil {
			return // io.EOF, io.ErrUnexpectedEOF (last partial), or a read error
		}
		if total >= maxFileScanBytes {
			rep.Findings = append(rep.Findings, Finding{
				Severity: Warn,
				What:     fmt.Sprintf("scanned only the first %d MiB; the rest is uninspected (payload could hide past the cap)", maxFileScanBytes>>20),
				Where:    rel,
			})
			return
		}
	}
}

// binaryExts are file types that are compiled/opaque, not source — a package
// shipping one is carrying code no static scan can read.
var binaryExts = map[string]bool{
	".node": true, ".wasm": true, ".exe": true, ".dll": true,
	".so": true, ".dylib": true, ".a": true, ".bin": true,
}

// capabilityFinders adapts capabilityPatterns to the generic finder shape so
// the capability sweep and injection sweep share one matching routine.
var capabilityFinders = func() []finder {
	fs := make([]finder, len(capabilityPatterns))
	for i, cp := range capabilityPatterns {
		fs[i] = finder{cp.re, cp.what, cp.sev}
	}
	return fs
}()

// finder is one regex → finding mapping, used by scanPatterns.
type finder struct {
	re   *regexp.Regexp
	what string
	sev  Severity
}

// scanPatterns records the first match of each finder in src (deduped by What
// across the whole package via seen), tagging it with rel:line.
func scanPatterns(rel string, src []byte, finders []finder, rep *Report, seen map[string]bool, lineBase int) {
	for _, f := range finders {
		if seen[f.what] {
			continue
		}
		if loc := f.re.FindIndex(src); loc != nil {
			seen[f.what] = true
			rep.Findings = append(rep.Findings, Finding{
				Severity: f.sev,
				What:     f.what,
				Where:    fmt.Sprintf("%s:%d", rel, lineBase+lineAt(src, loc[0])),
			})
		}
	}
}

// scanInjection runs the LLM-injection heuristics over a file: prose phrases,
// bidirectional control characters (the Trojan-Source attack — only meaningful
// in code), and zero-width characters used to hide content. All are deduped by
// What across the package so one finding flags the whole package.
func scanInjection(rel string, src []byte, code bool, rep *Report, seen map[string]bool, lineBase int) {
	const injWhat = "embedded instructions aimed at an LLM/agent reviewer"
	if !seen[injWhat] {
		for _, re := range injectionPatterns {
			if loc := re.FindIndex(src); loc != nil {
				seen[injWhat] = true
				rep.Findings = append(rep.Findings, Finding{
					Severity: Danger,
					What:     injWhat,
					Where:    fmt.Sprintf("%s:%d", rel, lineBase+lineAt(src, loc[0])),
				})
				break
			}
		}
	}

	// Invisible Unicode. Bidi controls reorder how source READS vs how it
	// COMPILES (Trojan Source) — never legitimate in code. Zero-width chars
	// hide content from a human/agent skimming the file. Scan rune by rune so
	// we can name the offending code point and its line.
	const bidiWhat = "bidirectional control character (Trojan Source) in source"
	const zwWhat = "zero-width character hiding content"
	for off, r := range string(src) {
		if isBidiControl(r) && code && !seen[bidiWhat] {
			seen[bidiWhat] = true
			rep.Findings = append(rep.Findings, Finding{
				Severity: Danger,
				What:     bidiWhat,
				Where:    fmt.Sprintf("%s:%d (U+%04X)", rel, lineBase+lineAt(src, off), r),
			})
		}
		if isZeroWidth(r) && !seen[zwWhat] {
			// Keep this quiet on legitimate uses or it becomes noise: emoji
			// ZWJ/ZWNJ sequences and a leading BOM are normal in prose. In
			// CODE, any zero-width char is suspect; in TEXT, only the "hiding"
			// ones (ZWSP/WJ, or a BOM that isn't at the very start).
			legitInText := r == 0x200C || r == 0x200D || (r == 0xFEFF && off == 0)
			if code || !legitInText {
				seen[zwWhat] = true
				rep.Findings = append(rep.Findings, Finding{
					Severity: Warn,
					What:     zwWhat,
					Where:    fmt.Sprintf("%s:%d (U+%04X)", rel, lineBase+lineAt(src, off), r),
				})
			}
		}
	}
}

// lineAt returns the 1-based line number of byte offset off in src.
func lineAt(src []byte, off int) int { return 1 + strings.Count(string(src[:off]), "\n") }

// codeExts / textBases decide which files get which sweep.
var codeExts = map[string]bool{
	".js": true, ".cjs": true, ".mjs": true,
	".ts": true, ".cts": true, ".mts": true, ".tsx": true, ".jsx": true,
}

// isCodeFile reports whether path is JS/TS source (gets the capability sweep).
func isCodeFile(path string) bool { return codeExts[filepath.Ext(path)] }

// isTextFile reports whether path is human-facing prose or manifest where an
// injection payload would hide (README, markdown, plain text, package.json).
func isTextFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if base == "package.json" || strings.HasPrefix(base, "readme") {
		return true
	}
	switch filepath.Ext(base) {
	case ".md", ".markdown", ".txt", ".rst":
		return true
	}
	return false
}

// isBidiControl reports whether r is a Unicode bidirectional override/embed/
// isolate control — the building blocks of the Trojan-Source attack. Written
// as code points on purpose: these characters are invisible, so spelling them
// literally in source would be unreviewable (and would trip this very check).
func isBidiControl(r rune) bool {
	switch r {
	case 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, // LRE RLE PDF LRO RLO
		0x2066, 0x2067, 0x2068, 0x2069: // LRI RLI FSI PDI
		return true
	}
	return false
}

// isZeroWidth reports whether r renders as nothing — used to smuggle content
// past a human or agent skim.
func isZeroWidth(r rune) bool {
	switch r {
	case 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF: // ZWSP ZWNJ ZWJ WJ BOM
		return true
	}
	return false
}
