package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Item 201. A bundle plus its source map is a reversible pair: the map carries
// the original files in sourcesContent. This writes them back out, keeping the
// tree the map names, and refuses any name that would leave the directory.

func init() {
	registerOp(op{
		name:  "recover_javascript_sources",
		route: "L",
		desc:  "recover original sources from a script's source map sourcesContent into <script>.sources/",
		needs: true,
		run:   opRecoverJavascriptSources,
	})
}

type sourceRecovery struct {
	Script    string   `json:"script"`
	Map       string   `json:"map"`
	Dir       string   `json:"dir"`
	Sources   int      `json:"sources"`
	Recovered []string `json:"recovered"`
	Bytes     int      `json:"bytes"`
	Missing   []string `json:"missing"`
	Refused   []string `json:"refused"`
}

func opRecoverJavascriptSources(script string) (any, error) {
	b, err := readCapped(script, maxMetaRead)
	if err != nil {
		return nil, err
	}
	var sm *webSourceMap
	var where string
	if strings.HasSuffix(strings.ToLower(script), ".map") {
		sm, where, err = decodeMapFile(script, b)
	} else {
		sm, where, err = loadSourceMap(script, b)
	}
	if err != nil {
		return nil, err
	}
	if len(sm.SourcesContent) == 0 {
		return nil, fmt.Errorf("%s has no sourcesContent: the map names %d sources but did not embed them (a served map usually does)", where, len(sm.Sources))
	}
	out := sourceRecovery{
		Script:  filepath.Base(script),
		Map:     filepath.Base(where),
		Dir:     script + ".sources",
		Sources: len(sm.Sources),
	}
	if err := os.MkdirAll(out.Dir, 0o755); err != nil {
		return nil, err
	}
	names := resolveMapSources(sm)
	for i, content := range sm.SourcesContent {
		if i >= len(names) {
			break
		}
		name := names[i]
		if content == nil {
			out.Missing = append(out.Missing, name)
			continue
		}
		clean := path.Clean(strings.TrimPrefix(name, "/"))
		// path.Clean does not treat `\` as a separator, so a backslash name
		// would ride through clean and escape the tree on Windows.
		if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || filepath.IsAbs(clean) || strings.Contains(clean, `\`) {
			out.Refused = append(out.Refused, name)
			continue
		}
		dst := filepath.Join(out.Dir, filepath.FromSlash(clean))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(dst, []byte(*content), 0o644); err != nil {
			return nil, err
		}
		out.Recovered = append(out.Recovered, clean)
		out.Bytes += len(*content)
	}
	if len(out.Recovered) == 0 {
		return nil, fmt.Errorf("%s has no usable sources: %d refused, %d absent", where, len(out.Refused), len(out.Missing))
	}
	return out, nil
}
