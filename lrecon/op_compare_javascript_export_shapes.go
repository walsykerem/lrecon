package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Item 185. Two builds of one library, compared by what they export: name plus
// arity, because a changed parameter list is the break a caller feels. The
// single-target CLI has no room for two paths, so the target is a directory that
// holds exactly two script files; the convention is named in the error.

func init() {
	registerOp(op{
		name:  "compare_javascript_export_shapes",
		route: "L",
		desc:  "compare (name, arity) export tables of the two script files in a directory: added, removed, arity-changed",
		needs: true,
		run:   opCompareJavascriptExportShapes,
	})
}

type exportShapeDiff struct {
	Old       string              `json:"old"`
	New       string              `json:"new"`
	Added     []jsExport          `json:"added"`
	Removed   []jsExport          `json:"removed"`
	Changed   []exportArityChange `json:"changed"`
	Same      int                 `json:"same"`
	Identical bool                `json:"identical"`
}

type exportArityChange struct {
	Name string `json:"name"`
	From int    `json:"from"`
	To   int    `json:"to"`
}

func opCompareJavascriptExportShapes(dir string) (any, error) {
	st, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is one file: this item compares two builds, so pass a directory holding exactly two script files", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var scripts []string
	for _, e := range entries {
		if !e.IsDir() && isScriptPath(e.Name()) {
			scripts = append(scripts, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(scripts)
	if len(scripts) != 2 {
		return nil, fmt.Errorf("%s holds %d script files, want 2: put the old and the new build side by side", dir, len(scripts))
	}
	// Lexical order puts new.js before old.js, so the naming convention wins.
	if strings.Contains(filepath.Base(scripts[0]), "new") && strings.Contains(filepath.Base(scripts[1]), "old") {
		scripts[0], scripts[1] = scripts[1], scripts[0]
	}
	oldSrc, oldCut, err := readWebText(scripts[0])
	if err != nil {
		return nil, err
	}
	if oldCut {
		return nil, fmt.Errorf("%s is over the %d-byte read cap: a partly read script would produce a wrong export table", scripts[0], maxWebText)
	}
	newSrc, newCut, err := readWebText(scripts[1])
	if err != nil {
		return nil, err
	}
	if newCut {
		return nil, fmt.Errorf("%s is over the %d-byte read cap: a partly read script would produce a wrong export table", scripts[1], maxWebText)
	}
	oldTable := exportTable(oldSrc)
	newTable := exportTable(newSrc)
	// An empty table is not "no changes": it means the parse found nothing, and
	// reporting the two builds as identical would be the worst kind of wrong.
	if len(oldTable) == 0 || len(newTable) == 0 {
		empty := scripts[1]
		if len(oldTable) == 0 {
			empty = scripts[0]
		}
		return nil, fmt.Errorf("%s: no exports found (%d on the old side, %d on the new): an empty table cannot be diffed", empty, len(oldTable), len(newTable))
	}
	diff := exportShapeDiff{Old: filepath.Base(scripts[0]), New: filepath.Base(scripts[1])}
	for name, a := range oldTable {
		b, ok := newTable[name]
		switch {
		case !ok:
			diff.Removed = append(diff.Removed, a)
		case a.Arity != b.Arity:
			diff.Changed = append(diff.Changed, exportArityChange{Name: name, From: a.Arity, To: b.Arity})
		default:
			diff.Same++
		}
	}
	for name, b := range newTable {
		if _, ok := oldTable[name]; !ok {
			diff.Added = append(diff.Added, b)
		}
	}
	sort.Slice(diff.Added, func(i, j int) bool { return diff.Added[i].Name < diff.Added[j].Name })
	sort.Slice(diff.Removed, func(i, j int) bool { return diff.Removed[i].Name < diff.Removed[j].Name })
	sort.Slice(diff.Changed, func(i, j int) bool { return diff.Changed[i].Name < diff.Changed[j].Name })
	diff.Identical = len(diff.Added) == 0 && len(diff.Removed) == 0 && len(diff.Changed) == 0
	return diff, nil
}

// exportTable indexes one build's exports by name, first sighting wins.
func exportTable(src string) map[string]jsExport {
	masked, _ := lexJS([]byte(src))
	out := map[string]jsExport{}
	for _, e := range jsExports(src, masked) {
		if _, ok := out[e.Name]; !ok {
			out[e.Name] = e
		}
	}
	return out
}
