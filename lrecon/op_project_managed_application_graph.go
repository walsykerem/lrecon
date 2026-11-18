package main

import (
	"fmt"
)

func init() {
	registerOp(op{
		name:  "project_managed_application_graph",
		route: "L",
		needs: true,
		desc:  "Project a .NET assembly into a graph: module -> assembly -> referenced assemblies -> types, with contains/extends/references edges from the CLI tables.",
		run:   runProjectManagedGraph,
	})
}

func runProjectManagedGraph(path string) (any, error) {
	job, err := metaLoadJob(path)
	if err != nil {
		return nil, err
	}
	target := job.File
	if target == "" {
		target = path
	}
	facts, err := metaCLI(target)
	if err != nil {
		return nil, err
	}
	mod := metaNode{Kind: "module", Name: facts.Module}
	asm := metaNode{Kind: "assembly", Name: facts.Assembly}
	nodes := []metaNode{mod}
	var edges []metaEdge
	if asm.Name != "" {
		nodes = append(nodes, asm)
		edges = append(edges, metaEdge{From: mod.Name, To: asm.Name, Kind: "contains"})
	}
	for _, r := range facts.AsmRefs {
		nodes = append(nodes, metaNode{Kind: "assembly-ref", Name: r})
		edges = append(edges, metaEdge{From: asm.Name, To: r, Kind: "references"})
	}
	for _, t := range facts.Types {
		node := metaNode{Kind: "type", Name: t.Name, Super: t.Extends, Methods: t.Methods}
		nodes = append(nodes, node)
		edges = append(edges, metaEdge{From: asm.Name, To: t.Name, Kind: "contains"})
		if t.Extends != "" {
			edges = append(edges, metaEdge{From: t.Name, To: t.Extends, Kind: "extends"})
		}
	}
	if len(facts.Types) == 0 {
		return nil, fmt.Errorf("project_managed_application_graph: %s has no CLI type definitions", target)
	}
	res := metaGraphResult(nodes, edges)
	res["file"] = target
	res["fields"], res["member_refs"], res["type_refs"] = len(facts.Fields), len(facts.Refs), len(facts.TypeRefs)
	return res, nil
}
