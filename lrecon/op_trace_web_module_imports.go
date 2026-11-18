package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
)

// Item 203. One bundle's edges stop at names; the graph only exists once those
// names are resolved to files and the files are read in turn. DFS from the entry
// file, each file visited once, and every spec recorded as resolved+read,
// resolved+missing (a real gap), or external (bare spec: left to node_modules).

func init() {
	registerOp(op{
		name:  "trace_web_module_imports",
		route: "L",
		desc:  "walk import/require edges from one entry script (each file once) into a module to resolved-file graph",
		needs: true,
		run:   opTraceWebModuleImports,
	})
}

const maxModuleWalk = 2000

type importRow struct {
	Spec     string `json:"spec"`
	Kind     string `json:"kind"`
	Line     int    `json:"line"`
	Resolved string `json:"resolved,omitempty"`
	Status   string `json:"status"` // read | missing | external | outside
}

type moduleGraph struct {
	Entry     string                 `json:"entry"`
	Files     []string               `json:"files"`
	Edges     map[string][]importRow `json:"edges"`
	Read      int                    `json:"read"`
	Missing   []string               `json:"missing"`
	External  []string               `json:"external"`
	NotWalked bool                   `json:"truncated"`
}

func opTraceWebModuleImports(entry string) (any, error) {
	st, err := os.Stat(entry)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, fmt.Errorf("%s is a directory: pass the entry script to walk from", entry)
	}
	entryAbs, err := filepath.Abs(entry)
	if err != nil {
		return nil, err
	}
	g := moduleGraph{Entry: filepath.Base(entryAbs), Edges: map[string][]importRow{}}
	seen := map[string]bool{}
	external := map[string]bool{}
	var missing []string
	queue := []string{entry}
	for len(queue) > 0 {
		file := queue[0]
		queue = queue[1:]
		abs, err := filepath.Abs(file)
		if err != nil {
			return nil, err
		}
		if seen[abs] {
			continue
		}
		seen[abs] = true
		if g.Read >= maxModuleWalk {
			g.NotWalked = true
			break
		}
		src, cut, err := readWebText(file)
		if err != nil {
			return nil, err
		}
		if cut {
			return nil, fmt.Errorf("%s is over the %d-byte read cap: its import edges would be missing from the graph", file, maxWebText)
		}
		masked, _ := lexJS([]byte(src))
		// Key by path relative to the entry, not by basename: two util.js files
		// in different directories are different nodes, and merging them hides
		// both an edge and a missing file.
		key := relativeOrBase(entryAbs, abs)
		for _, e := range jsEdges(src, masked) {
			row := importRow{Spec: e.Spec, Kind: e.Kind, Line: e.Line}
			if !isRelativeSpec(e.Spec) {
				row.Status = "external"
				external[e.Spec] = true
				g.Edges[key] = append(g.Edges[key], row)
				continue
			}
			next, status := resolveRelative(file, e.Spec)
			row.Status = status
			if next != "" {
				// Graph nodes are keyed from the entry dir, so the resolved
				// value is too: a relative-to-this-file path would name a node
				// that does not exist in Edges.
				if nabs, aerr := filepath.Abs(next); aerr == nil {
					row.Resolved = relativeOrBase(entryAbs, nabs)
				}
			}
			g.Edges[key] = append(g.Edges[key], row)
			switch status {
			case "read":
				queue = append(queue, next)
			case "missing":
				missing = append(missing, e.Spec)
			}
		}
		g.Read++
		g.Files = append(g.Files, key)
	}
	sort.Strings(g.Files)
	for spec := range external {
		g.External = append(g.External, spec)
	}
	sort.Strings(g.External)
	sort.Strings(missing)
	g.Missing = missing
	return g, nil
}

func isRelativeSpec(spec string) bool {
	return len(spec) > 1 && spec[0] == '.' && (spec[1] == '/' || (spec[1] == '.' && len(spec) > 2 && spec[2] == '/'))
}

// resolveRelative turns './a' / '../b' into a real file, trying the extension
// forms a bundler would have produced.
func resolveRelative(from, spec string) (string, string) {
	base := filepath.Join(filepath.Dir(from), filepath.FromSlash(spec))
	if filepath.IsAbs(base) && !within(filepath.Dir(from), base) {
		return "", "outside"
	}
	cands := []string{base}
	if filepath.Ext(base) == "" {
		cands = append(cands, base+".js", base+".mjs", base+".cjs", base+".json", filepath.Join(base, "index.js"))
	}
	for _, c := range cands {
		st, err := os.Stat(c)
		if err == nil && !st.IsDir() {
			return c, "read"
		}
	}
	return "", "missing"
}

func within(dir, p string) bool {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return false
	}
	return len(abs) > len(dir) && abs[:len(dir)+1] == dir+string(filepath.Separator)
}

func relativeOrBase(from, to string) string {
	rel, err := filepath.Rel(filepath.Dir(from), to)
	if err != nil {
		return path.Base(filepath.ToSlash(to))
	}
	return filepath.ToSlash(rel)
}
