package lockfile

// Dependency-graph reconstruction for `guard why` — the only consumer that
// needs PARENT→CHILD edges, not just the flat name@version set the checks use.
// npm's package-lock.json (v2/v3) records each package's own `dependencies`
// (and dev/optional/peer) map, so we can rebuild "who pulled in X" at the name
// level without resolving exact versions: the question a human asks is "which
// of MY direct deps drags this transitive package in", and a name-level path
// answers that. pnpm/yarn lockfiles don't carry a full graph in a form we parse
// zero-dep, so Graph is npm-only and callers surface a clear "needs
// package-lock.json" message for the others.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Graph is the name-level dependency graph of an npm lockfile.
type Graph struct {
	// Roots are the project's DIRECT dependency names (prod + dev + optional):
	// the entries declared in the root package, i.e. the only legitimate
	// "reasons" a transitive package can be present.
	Roots map[string]bool
	// Edges maps a package name to the set of names it directly depends on.
	Edges map[string]map[string]bool
	// Versions maps a package name to the set of installed versions of it,
	// so `why` can report exactly which version(s) of the target are present.
	Versions map[string]map[string]bool
}

// lockPkgDeps is the subset of a lockfile package entry the graph needs: the
// declared dependency maps (values are version RANGES we deliberately ignore —
// only the names matter for a "why" path).
type lockPkgDeps struct {
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

// allDeps returns the union of every declared dependency name for an entry.
func (p lockPkgDeps) allDeps() []string {
	var out []string
	for _, m := range []map[string]string{p.Dependencies, p.DevDependencies, p.OptionalDependencies, p.PeerDependencies} {
		for name := range m {
			out = append(out, name)
		}
	}
	return out
}

// BuildGraph reads the npm package-lock.json in dir and reconstructs the
// name-level dependency graph. Returns os.ErrNotExist when there is no
// package-lock.json (the caller distinguishes "no npm lockfile" from a real
// parse error, since pnpm/yarn aren't supported here).
func BuildGraph(dir string) (*Graph, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "package-lock.json"))
	if err != nil {
		return nil, err // includes os.ErrNotExist — caller maps it to a helpful message
	}
	var lock struct {
		LockfileVersion int                    `json:"lockfileVersion"`
		Packages        map[string]lockPkgDeps `json:"packages"`
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("parse package-lock.json: %w", err)
	}
	if lock.Packages == nil {
		return nil, fmt.Errorf("package-lock.json v%d has no packages map (npm <7?)", lock.LockfileVersion)
	}

	g := &Graph{
		Roots:    map[string]bool{},
		Edges:    map[string]map[string]bool{},
		Versions: map[string]map[string]bool{},
	}
	for path, p := range lock.Packages {
		// The root project is the "" key: its declared deps are the Roots.
		if path == "" {
			for _, name := range p.allDeps() {
				g.Roots[name] = true
			}
			continue
		}
		idx := strings.LastIndex(path, "node_modules/")
		if idx < 0 {
			continue // workspace/link entry — not a registry package
		}
		name := path[idx+len("node_modules/"):]
		if name == "" {
			continue
		}
		if p.Version != "" {
			if g.Versions[name] == nil {
				g.Versions[name] = map[string]bool{}
			}
			g.Versions[name][p.Version] = true
		}
		for _, dep := range p.allDeps() {
			if g.Edges[name] == nil {
				g.Edges[name] = map[string]bool{}
			}
			g.Edges[name][dep] = true
		}
	}
	return g, nil
}

// Paths returns dependency paths from a direct (root) dependency down to
// target, each path a name slice like ["express", "body-parser", "qs"]. It
// walks PARENT→CHILD edges breadth-first from every root, so the shortest
// route through each root surfaces first. maxPaths caps the result (0 = no
// cap) to keep deep graphs from exploding; visited-set per walk prevents
// cycles. An empty result means target isn't reachable from any root (it may
// not be installed, or only present as an unreferenced entry).
func (g *Graph) Paths(target string, maxPaths int) [][]string {
	var out [][]string
	// One BFS per root keeps each returned path rooted at a real direct dep
	// and naturally yields the shortest path through that root first.
	roots := make([]string, 0, len(g.Roots))
	for r := range g.Roots {
		roots = append(roots, r)
	}
	sort.Strings(roots) // deterministic output
	for _, root := range roots {
		if root == target {
			out = append(out, []string{root})
			if maxPaths > 0 && len(out) >= maxPaths {
				return out
			}
			continue
		}
		queue := [][]string{{root}}
		for len(queue) > 0 {
			path := queue[0]
			queue = queue[1:]
			last := path[len(path)-1]
			for child := range g.Edges[last] {
				if inPath(path, child) {
					continue // cycle guard
				}
				next := append(append([]string{}, path...), child)
				if child == target {
					out = append(out, next)
					if maxPaths > 0 && len(out) >= maxPaths {
						return out
					}
					continue
				}
				queue = append(queue, next)
			}
		}
	}
	return out
}

// inPath reports whether name already appears in path (cycle guard).
func inPath(path []string, name string) bool {
	for _, p := range path {
		if p == name {
			return true
		}
	}
	return false
}

// SortedVersions returns the installed versions of name, sorted, or nil.
func (g *Graph) SortedVersions(name string) []string {
	vs := g.Versions[name]
	if len(vs) == 0 {
		return nil
	}
	out := make([]string, 0, len(vs))
	for v := range vs {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
