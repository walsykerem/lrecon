package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

// metaManagedImport is the on-disk contract: <out>/types.json holds the CLI
// tables, <out>/methods/<Type>.txt one name per line, <out>/README.md the map.
type metaManagedImport struct {
	Kind     string       `json:"kind"`
	Artifact string       `json:"artifact"`
	SHA256   string       `json:"sha256"`
	Facts    metaCLIFacts `json:"facts"`
}

const metaManagedKind = "lrecon.managed/1"

func init() {
	registerOp(op{
		name:  "import_managed_reconstruction",
		route: "L",
		needs: true,
		desc:  "Import a .NET assembly's CLI tables into a reconstruction tree: <out>/types.json, <out>/methods/<Type>.txt, <out>/README.md; a different artifact already in <out> is a conflict.",
		run:   runImportManagedReconstruction,
	})
}

func runImportManagedReconstruction(path string) (any, error) {
	job, err := metaLoadJob(path)
	if err != nil {
		return nil, err
	}
	target, err := metaGhidraTarget(path, job)
	if err != nil {
		return nil, err
	}
	facts, err := metaCLI(target)
	if err != nil {
		return nil, err
	}
	sum, _, err := metaObjectSHA(target)
	if err != nil {
		return nil, err
	}
	out := job.State
	if out == "" {
		out = target + ".managed"
	}
	root, err := metaMkdir(out)
	if err != nil {
		return nil, err
	}
	tree := metaManagedImport{Kind: metaManagedKind, Artifact: target, SHA256: sum, Facts: facts}
	typesFile := filepath.Join(root, "types.json")
	var prev metaManagedImport
	exists, err := metaReadState(typesFile, metaManagedKind, &prev)
	if err != nil {
		return nil, err
	}
	if exists && prev.SHA256 != sum {
		return nil, fmt.Errorf("state conflict: %s already holds the reconstruction of %s (sha256 %s), refusing to overwrite it with %s (%s)", root, prev.Artifact, prev.SHA256, target, sum)
	}
	if err := metaWriteJSON(typesFile, tree); err != nil {
		return nil, err
	}
	methodDir := filepath.Join(root, "methods")
	if _, err := metaMkdir(methodDir); err != nil {
		return nil, err
	}
	written := 0
	for _, t := range facts.Types {
		name := strings.NewReplacer("/", "_", "\\", "_", ".", ".", "`", "", "<", "", ">", "").Replace(t.Name)
		if name == "" {
			continue
		}
		var b strings.Builder
		fmt.Fprintf(&b, "# %s (extends %s)\n", t.Name, t.Extends)
		for _, m := range t.Methods {
			fmt.Fprintf(&b, "method %s\n", m)
		}
		for _, f := range t.Fields {
			fmt.Fprintf(&b, "field %s\n", f)
		}
		if err := metaWriteBytes(filepath.Join(methodDir, name+".txt"), []byte(b.String()), false); err != nil {
			return nil, err
		}
		written++
	}
	readme := fmt.Sprintf("# %s\n\n- artifact: %s\n- sha256: %s\n- assembly: %s\n- types: %d\n- type refs: %d\n- member refs: %d\n- assembly refs: %d\n\ntypes.json holds the CLI tables; methods/<Type>.txt holds the members of each type.\n",
		facts.Assembly, target, sum, facts.Assembly, len(facts.Types), len(facts.TypeRefs), len(facts.Refs), len(facts.AsmRefs))
	if err := metaWriteBytes(filepath.Join(root, "README.md"), []byte(readme), false); err != nil {
		return nil, err
	}
	return map[string]any{
		"out":           root,
		"types_file":    typesFile,
		"methods":       written,
		"artifact":      target,
		"sha256":        sum,
		"assembly":      facts.Assembly,
		"types":         len(facts.Types),
		"type_refs":     facts.TypeRefs,
		"member_refs":   facts.Refs,
		"assembly_refs": facts.AsmRefs,
	}, nil
}
