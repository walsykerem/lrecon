package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

func init() {
	registerOp(op{
		name:  "project_harmony_application_graph",
		route: "L",
		needs: true,
		desc:  "Project a HarmonyOS HAP into a graph: module.json identity, the abc bytecode module and the native libs, member by member from the archive.",
		run:   runProjectHarmonyGraph,
	})
}

func runProjectHarmonyGraph(path string) (any, error) {
	job, err := metaLoadJob(path)
	if err != nil {
		return nil, err
	}
	target := job.File
	if target == "" {
		target = path
	}
	members, format, err := metaArchiveMembers(target)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(members))
	for n := range members {
		names = append(names, n)
	}
	sort.Strings(names)
	bundle := metaNode{Kind: "hap", Name: filepath.Base(target), Detail: format}
	nodes := []metaNode{bundle}
	var edges []metaEdge
	found := 0
	for _, n := range names {
		switch {
		case n == "module.json" || strings.HasSuffix(n, "/module.json"):
			b, err := metaArchiveMember(target, n)
			if err != nil {
				return nil, err
			}
			var m struct {
				Module struct {
					Name        string   `json:"name"`
					MainElement string   `json:"mainElement"`
					DeviceTypes []string `json:"deviceTypes"`
					Abilities   []struct {
						Name string `json:"name"`
					} `json:"abilities"`
				} `json:"module"`
				App struct {
					BundleName  string `json:"bundleName"`
					VersionName string `json:"versionName"`
				} `json:"app"`
			}
			if err := json.Unmarshal(b, &m); err != nil {
				return nil, fmt.Errorf("%s is not valid JSON: %v", n, err)
			}
			mod := metaNode{Kind: "module", Name: m.Module.Name, Detail: m.App.BundleName + "@" + m.App.VersionName}
			nodes = append(nodes, mod)
			edges = append(edges, metaEdge{From: bundle.Name, To: mod.Name, Kind: "contains"})
			for _, a := range m.Module.Abilities {
				nodes = append(nodes, metaNode{Kind: "ability", Name: a.Name})
				edges = append(edges, metaEdge{From: mod.Name, To: a.Name, Kind: "declares"})
			}
			found++
		case strings.HasSuffix(n, ".abc"):
			nodes = append(nodes, metaNode{Kind: "abc", Name: n, Detail: fmt.Sprintf("sha256=%s", members[n])})
			edges = append(edges, metaEdge{From: bundle.Name, To: n, Kind: "contains"})
			found++
		case strings.Contains(n, "/libs/") && strings.HasSuffix(n, ".so"):
			nodes = append(nodes, metaNode{Kind: "native-lib", Name: n, Detail: fmt.Sprintf("sha256=%s", members[n])})
			edges = append(edges, metaEdge{From: bundle.Name, To: n, Kind: "contains"})
			found++
		}
	}
	if found == 0 {
		return nil, fmt.Errorf("project_harmony_application_graph: %s has no module.json, .abc or libs/*.so (format %s)", target, format)
	}
	res := metaGraphResult(nodes, edges)
	res["file"] = target
	res["format"] = format
	return res, nil
}
