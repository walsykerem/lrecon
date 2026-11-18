package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// Item 200. y73: the runtime says which scripts it parsed; the static side says
// which exports a bundle has. Joining them needs no getScriptSource (it returns
// the generated bundle, not the map's sources). A file only on disk is
// "not-parsed", never "dead": a lazy chunk may simply not have loaded yet.

func init() {
	registerOp(op{
		name:  "reconcile_javascript_runtime",
		route: "Y",
		desc:  "join Debugger.scriptParsed URLs (asar-relative) with a local bundle's export table",
		needs: true,
		run:   opReconcileJavascriptRuntime,
	})
}

type reconcileReport struct {
	Static       string      `json:"static"`
	Parsed       int         `json:"scripts_parsed"`
	Matched      []string    `json:"matched"`
	RuntimeOnly  []scriptRow `json:"runtime_only"`
	RuntimeNames []string    `json:"runtime_exports_only"`
	DiskOnly     []jsExport  `json:"disk_only_not_parsed"`
	Evaluated    bool        `json:"exports_evaluated"`
	Status       string      `json:"status"`
}

func opReconcileJavascriptRuntime(target string) (any, error) {
	ep, arg, err := webTarget(target)
	if err != nil {
		return nil, err
	}
	if arg == "" {
		return nil, fmt.Errorf("no static bundle: pass <endpoint>=<bundle.js> so the runtime scripts have something to join with")
	}
	src, _, err := readWebText(arg)
	if err != nil {
		return nil, err
	}
	masked, _ := lexJS([]byte(src))
	exports := jsExports(src, masked)
	parsed := make([]scriptRow, 0, 8)
	out, sk, err := webRun("reconcile_javascript_runtime", ep, webSpec{
		Mode: "session",
		Steps: []webStep{{Method: "Debugger.enable"}, {Method: "Runtime.enable"},
			// Ask the running module what it exports; a CJS bundle hangs its
			// exports off `exports`, which is the only address the runtime shares
			// with the static table.
			{Method: "Runtime.evaluate", Params: map[string]any{
				"expression":    "(typeof exports==='object'&&exports!==null)?Object.keys(exports):null",
				"returnByValue": true,
			}}},
		Collect: &webCollect{Ms: 1200, Prefixes: []string{"Debugger.scriptParsed"}},
	})
	if sk != nil {
		return sk, nil
	}
	if err != nil {
		return nil, err
	}
	parsed = scriptsFrom(out.Events)
	res := reconcileReport{Static: filepath.Base(arg), Parsed: len(parsed), Status: "no-runtime-script"}
	runtimeNames := map[string]bool{}
	matchedScript := false
	for _, s := range parsed {
		// A webpack://, blob: or eval script has no file on disk to compare with,
		// which is exactly why it belongs in the runtime-only list.
		rel := asarMemberPath(s.URL)
		if rel != "" && strings.HasSuffix(rel, filepath.Base(arg)) {
			matchedScript = true
			continue
		}
		res.RuntimeOnly = append(res.RuntimeOnly, s)
	}
	known := map[string]bool{}
	for _, e := range exports {
		known[e.Name] = true
	}
	if len(out.Steps) > 2 && out.Steps[2].Ok {
		if keys, ok := nested(out.Steps[2].Result, "result", "value").([]any); ok {
			res.Evaluated = true
			for _, k := range keys {
				name, ok := k.(string)
				if !ok {
					continue
				}
				if !known[name] {
					res.RuntimeNames = append(res.RuntimeNames, name)
				}
				runtimeNames[name] = true
			}
			sort.Strings(res.RuntimeNames)
		}
	}
	if !res.Evaluated {
		// No `exports` object in this context (an ESM page, say): the only honest
		// join left is "was the script parsed", not what it exports.
		if matchedScript {
			for _, e := range exports {
				runtimeNames[e.Name] = true
			}
		}
	}
	for _, e := range exports {
		if runtimeNames[e.Name] {
			res.Matched = append(res.Matched, e.Name)
			continue
		}
		res.DiskOnly = append(res.DiskOnly, e)
	}
	sort.Strings(res.Matched)
	switch {
	case len(res.Matched) > 0:
		res.Status = "matched"
	case len(parsed) > 0:
		res.Status = "no-matching-script"
	}
	return res, nil
}
