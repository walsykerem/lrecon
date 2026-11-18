package main

import (
	"fmt"
	"sort"
)

// An ext op is an inventory item that drives an installed external tool:
// adb, lldb, jadx, apktool, analyzeHeadless. It lives on its own CLI
// surface, so the published --op inventory (229 items, testdata/ops.json)
// stays exactly as it is and the two tables cannot drift into each other.
//
//	lrecon --ext-op <name> [target] [arg...]
//	lrecon --list-ext-ops
type extOp struct {
	name  string
	route string // Y: external tool, G: ghidra headless
	desc  string
	// needs says whether the item wants a target path. A tool-inventory item
	// (adb version, jadx plugins) answers without a file.
	needs bool
	run   func(path string, args []string) (any, error)
}

var extOps = map[string]extOp{}

func registerExtOp(o extOp) {
	if o.name == "" || o.run == nil {
		panic("registerExtOp: ext op without name or run")
	}
	if o.desc == "" {
		panic("registerExtOp: " + o.name + " has no description")
	}
	switch o.route {
	case "L", "G", "Y":
	default:
		panic("registerExtOp: " + o.name + " has route " + o.route)
	}
	if _, dup := extOps[o.name]; dup {
		panic("registerExtOp: duplicate ext op: " + o.name)
	}
	extOps[o.name] = o
}

// runExtOp runs one ext item. A missing target is refused before any tool is
// touched, so the no-target pass spawns nothing.
func runExtOp(name, path string, args []string) (any, error) {
	o, ok := extOps[name]
	if !ok {
		return nil, fmt.Errorf("unknown ext op %q (%d registered; see --list-ext-ops)", name, len(extOps))
	}
	if o.needs && path == "" {
		return nil, fmt.Errorf("op %q needs a target path", name)
	}
	return o.run(path, args)
}

// extOpNames is sorted so --list-ext-ops and every proof built on it are stable.
func extOpNames() []string {
	names := make([]string, 0, len(extOps))
	for name := range extOps {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
