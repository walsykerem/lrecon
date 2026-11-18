package main

import (
	"os"
	"sort"
	"strings"
)

func init() {
	registerOp(op{
		name:  "compare_source_to_bundle",
		route: "L",
		needs: true,
		desc:  "match the asar file list against the source maps the digest found (bundle.asar)",
		run: func(path string) (any, error) {
			f, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			root, _, err := asarHeader(f, path)
			if err != nil {
				return nil, err
			}
			files := map[string]bool{}
			walkAsarFiles(root, "", files)
			d, err := Probe(path)
			if err != nil {
				return nil, err
			}
			res := struct {
				Scripts     int      `json:"scripts"`
				Maps        int      `json:"maps"`
				DigestMaps  int      `json:"digest_source_maps"`
				MissingMaps []string `json:"scripts_without_map,omitempty"`
				OrphanMaps  []string `json:"maps_without_script,omitempty"`
				// The lists are capped at 50; the totals keep a capped list
				// from reading as the whole story.
				MissingTotal int `json:"scripts_without_map_total"`
				OrphanTotal  int `json:"maps_without_script_total"`
			}{DigestMaps: len(d.SourceMaps)}
			for n := range files {
				if !isScriptName(n) {
					continue
				}
				res.Scripts++
				if !files[n+".map"] {
					res.MissingMaps = append(res.MissingMaps, n)
				}
			}
			for n := range files {
				if !strings.HasSuffix(n, ".map") {
					continue
				}
				res.Maps++
				if !files[strings.TrimSuffix(n, ".map")] {
					res.OrphanMaps = append(res.OrphanMaps, n)
				}
			}
			sort.Strings(res.MissingMaps)
			sort.Strings(res.OrphanMaps)
			res.MissingTotal = len(res.MissingMaps)
			res.OrphanTotal = len(res.OrphanMaps)
			res.MissingMaps = cap50(res.MissingMaps)
			res.OrphanMaps = cap50(res.OrphanMaps)
			return res, nil
		},
	})
}

func isScriptName(n string) bool {
	for _, ext := range []string{".js", ".mjs", ".cjs"} {
		if strings.HasSuffix(n, ext) {
			return true
		}
	}
	return false
}

// walkAsarFiles flattens the asar header tree into "path/file" keys.
func walkAsarFiles(n *asarNode, prefix string, out map[string]bool) {
	for name, child := range n.Files {
		if child == nil {
			continue
		}
		p := prefix + name
		if child.Files != nil {
			walkAsarFiles(child, p+"/", out)
			continue
		}
		if child.Link == "" {
			out[p] = true
		}
	}
}
