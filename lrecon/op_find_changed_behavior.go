package main

import (
	"fmt"
	"strings"
)

// metaBehavior is one observable difference between two builds, classified by
// the kind of behavior it can change.
type metaBehavior struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Before any    `json:"before"`
	After  any    `json:"after"`
}

// metaBehaviorKinds maps a digest path onto the behavior it can move. This is a
// lookup over names, not a guess about the code: unmapped paths stay "other".
func metaBehaviorKind(path string) string {
	base, _, _ := strings.Cut(path, ".")
	switch base {
	case "kind", "format", "slice_info":
		return "executable-format"
	case "minos", "subsystem":
		return "os-floor"
	case "deps", "imports", "dylibs":
		return "dependency"
	case "capabilities":
		return "capability"
	case "mobile_permissions":
		return "permission"
	case "plist_keys":
		return "declared-key"
	case "asar_version", "asar_product", "asar_main", "electron", "flutter_hash":
		return "application-identity"
	case "hardening":
		return "hardening"
	case "symbols", "exports", "names", "skeleton":
		return "code-surface"
	case "constants":
		return "crypto-constant"
	case "ipc", "source_maps", "rust_crates":
		return "runtime-surface"
	}
	return "other"
}

func init() {
	registerOp(op{
		name:  "find_changed_behavior",
		route: "L",
		needs: true,
		desc:  "Diff two builds and keep only differences that can change behavior, each labelled (dependency, permission, hardening, os-floor, code-surface...) with before/after values.",
		run:   runFindChangedBehavior,
	})
}

func runFindChangedBehavior(path string) (any, error) {
	job, err := metaLoadJob(path)
	if err != nil {
		return nil, err
	}
	aSide, a, bSide, b, err := metaComparePair(job)
	if err != nil {
		return nil, fmt.Errorf("find_changed_behavior: %v", err)
	}
	var out []metaBehavior
	byKind := map[string]int{}
	for _, c := range metaChanges(a, b) {
		kind := metaBehaviorKind(c.Path)
		if kind == "other" {
			continue
		}
		out = append(out, metaBehavior{Kind: kind, Path: c.Path, Before: c.Before, After: c.After})
		byKind[kind]++
	}
	return map[string]any{
		"old":       aSide,
		"new":       bSide,
		"behaviors": out,
		"count":     len(out),
		"by_kind":   byKind,
	}, nil
}
