package main

import (
	"path/filepath"
)

// Item 181. One bundle text, two views: the flat edge list (every import /
// require / export-from occurrence in source order) and the module → dependency
// map the same edges imply once duplicates are gone.

func init() {
	registerOp(op{
		name:  "analyze_web_bundle",
		route: "L",
		desc:  "extract import/require/export-from edges from one web bundle and dedupe them into a module to dependency map",
		needs: true,
		run:   opAnalyzeWebBundle,
	})
}

type webBundle struct {
	Bytes         int                 `json:"bytes"`
	Edges         []jsEdge            `json:"edges"`
	Count         int                 `json:"count"`
	Modules       int                 `json:"modules"`
	Graph         map[string][]string `json:"graph"`
	Truncated     bool                `json:"truncated"`
	CapBytes      int64               `json:"cap_bytes,omitempty"`
	TotalCapBytes int64               `json:"total_cap_bytes,omitempty"`
}

func opAnalyzeWebBundle(path string) (any, error) {
	// B9: same in-op budget as analyze_javascript_application.
	return runOpDeadline(path, func() (any, error) { return analyzeWebBundle(path) })
}

func analyzeWebBundle(path string) (any, error) {
	src, truncated, err := readWebTargetText(path)
	if err != nil {
		return nil, err
	}
	masked, _ := lexJS([]byte(src))
	edges := dedupeEdges(jsEdgesIndexed(src, masked, newLineIndex(src)))
	deps := make([]string, 0, len(edges))
	for _, e := range edges {
		deps = append(deps, e.Spec)
	}
	// uniqSorted sorts; the pre-sort that used to sit here was a second pass
	// over the same slice for no new ordering.
	deps = uniqSorted(deps)
	return webBundle{
		Bytes:     len(src),
		Edges:     edges,
		Count:     len(edges),
		Modules:   len(deps),
		Graph:     map[string][]string{filepath.Base(path): deps},
		Truncated: truncated,
		CapBytes:  extractLimit(), TotalCapBytes: extractTotalLimit(),
	}, nil
}
