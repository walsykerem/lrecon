package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Item 204. A source map is only useful if a generated line can be turned back
// into an original file and line. This decodes the mappings table (base64 VLQ,
// relative per segment) and reports what each generated position points at.

func init() {
	registerOp(op{
		name:  "trace_web_source_location",
		route: "L",
		desc:  "decode a source map v3 mappings table and report generated to original file/line/column per segment",
		needs: true,
		run:   opTraceWebSourceLocation,
	})
}

const (
	maxMapRows     = 256
	maxMapSegments = 200000
)

type mapRow struct {
	GenLine  int    `json:"generated_line"`
	GenCol   int    `json:"generated_column"`
	Source   string `json:"source"`
	OrigLine int    `json:"original_line"`
	OrigCol  int    `json:"original_column"`
	Name     string `json:"name,omitempty"`
}

type sourceLocationMap struct {
	Script    string         `json:"script"`
	Map       string         `json:"map"`
	Version   int            `json:"version"`
	Sources   []string       `json:"sources"`
	Segments  int            `json:"segments"`
	PerSource map[string]int `json:"segments_per_source"`
	Rows      []mapRow       `json:"rows"`
	Truncated bool           `json:"truncated"`
}

func opTraceWebSourceLocation(script string) (any, error) {
	st, err := os.Stat(script)
	if err != nil {
		return nil, err
	}
	out := sourceLocationMap{Script: filepath.Base(script)}
	var sm *webSourceMap
	var where string
	if st.IsDir() {
		return nil, fmt.Errorf("%s is a directory: pass one script that carries a sourceMappingURL", script)
	}
	if strings.HasSuffix(strings.ToLower(script), ".map") {
		b, err := opRead(script, opMaxFile)
		if err != nil {
			return nil, err
		}
		sm, where, err = decodeMapFile(script, b)
		if err != nil {
			return nil, err
		}
	} else {
		b, err := opRead(script, opMaxFile)
		if err != nil {
			return nil, err
		}
		sm, where, err = loadSourceMap(script, b)
		if err != nil {
			return nil, err
		}
	}
	out.Map = filepath.Base(where)
	out.Version = sm.Version
	out.Sources = resolveMapSources(sm)
	segs, err := decodeMappings(sm.Mappings, maxMapSegments)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", where, err)
	}
	out.Segments = len(segs)
	if len(segs) >= maxMapSegments {
		out.Truncated = true
	}
	out.PerSource = map[string]int{}
	for _, s := range segs {
		if s.Source < 0 || s.Source >= len(out.Sources) {
			continue
		}
		out.PerSource[out.Sources[s.Source]]++
		if len(out.Rows) >= maxMapRows {
			out.Truncated = true
			continue
		}
		row := mapRow{
			GenLine:  s.GenLine + 1,
			GenCol:   s.GenCol,
			Source:   out.Sources[s.Source],
			OrigLine: s.OrigLine + 1,
			OrigCol:  s.OrigCol,
		}
		if s.Name >= 0 && s.Name < len(sm.Names) {
			row.Name = sm.Names[s.Name]
		}
		out.Rows = append(out.Rows, row)
	}
	return out, nil
}

// decodeMapFile parses a map given as the target itself, so a .map whose script
// is gone still reports its table.
func decodeMapFile(p string, b []byte) (*webSourceMap, string, error) {
	var sm webSourceMap
	if err := json.Unmarshal(b, &sm); err != nil {
		return nil, "", fmt.Errorf("%s is not a JSON source map: %v", p, err)
	}
	if sm.Version != 3 {
		return nil, "", fmt.Errorf("%s is not a v3 source map (version %d); only v3 maps carry mappings", p, sm.Version)
	}
	return &sm, p, nil
}

// resolveMapSources applies sourceRoot once, the way a consumer does.
func resolveMapSources(sm *webSourceMap) []string {
	out := make([]string, len(sm.Sources))
	for i, s := range sm.Sources {
		if sm.SourceRoot == "" || strings.HasPrefix(s, "/") {
			out[i] = s
			continue
		}
		out[i] = path.Join(sm.SourceRoot, s)
	}
	return out
}
