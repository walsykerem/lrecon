package main

import (
	"fmt"
	"strconv"
	"strings"
)

// Item 202. y74: a breakpoint on the attached page's own URL at line N (the
// protocol counts from 0, the user counts from 1), the URL escaped so a dot in
// app.asar is not a wildcard. The driver removes the breakpoint and resumes
// whenever a pause was seen, so the target is never left frozen.

func init() {
	registerOp(op{
		name:  "trace_javascript_semantics",
		route: "Y",
		desc:  "pause the attached page at <endpoint>=<line> of its own URL and report the pause location",
		needs: true,
		run:   opTraceJavascriptSemantics,
	})
}

type pauseReport struct {
	Target     string   `json:"target,omitempty"`
	URL        string   `json:"url"`
	Line       int      `json:"line"`
	Breakpoint string   `json:"breakpoint_id"`
	Locations  []bpLoc  `json:"locations"`
	Paused     bool     `json:"paused"`
	Resumed    bool     `json:"resumed"`
	CallFrames []string `json:"call_frames,omitempty"`
}

type bpLoc struct {
	ScriptID string `json:"script_id"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
}

func opTraceJavascriptSemantics(target string) (any, error) {
	ep, arg, err := webTarget(target)
	if err != nil {
		return nil, err
	}
	line, err := strconv.Atoi(strings.TrimSpace(arg))
	if err != nil || line <= 0 {
		return nil, fmt.Errorf("no line to break on: pass <endpoint>=<line> using 1-based line numbers (the protocol gets line-1)")
	}
	out, sk, err := webRun("trace_javascript_semantics", ep, webSpec{
		Mode: "session",
		Steps: []webStep{
			{Method: "Debugger.enable"},
			{Method: "Debugger.setBreakpointByUrl", Params: map[string]any{
				"lineNumber": line - 1,
				"urlRegex":   "$target.urlQuote",
			}},
			// The page has to execute the line for the pause to happen.
			{Method: "Debugger.setPauseOnExceptions", Params: map[string]any{"state": "none"}},
		},
		Collect: &webCollect{Ms: 1500, Prefixes: []string{"Debugger."}},
		Resume:  true,
	})
	if sk != nil {
		return sk, nil
	}
	if err != nil {
		return nil, err
	}
	res := pauseReport{Line: line, Resumed: out.Resumed}
	if out.Target != nil {
		res.Target = out.Target.ID
		res.URL = out.Target.URL
	}
	if len(out.Steps) < 2 || !out.Steps[1].Ok {
		return nil, fmt.Errorf("cdp %s: setBreakpointByUrl: %s", ep, stepFailure(out.Steps, 1))
	}
	res.Breakpoint = str(out.Steps[1].Result["breakpointId"])
	locs, _ := out.Steps[1].Result["locations"].([]any)
	for _, l := range locs {
		m, _ := l.(map[string]any)
		res.Locations = append(res.Locations, bpLoc{
			ScriptID: str(m["scriptId"]),
			Line:     int(num(m["lineNumber"])) + 1,
			Column:   int(num(m["columnNumber"])),
		})
	}
	for _, e := range out.Events {
		if e.Method != "Debugger.paused" {
			continue
		}
		res.Paused = true
		frames, _ := e.Params["callFrames"].([]any)
		for _, f := range frames {
			m, _ := f.(map[string]any)
			res.CallFrames = append(res.CallFrames, str(m["functionName"])+"@"+str(m["url"]))
		}
	}
	if len(res.Locations) == 0 && !res.Paused {
		return nil, fmt.Errorf("cdp %s: line %d of %s never resolved and never paused: the script may not be loaded in this target", ep, line, res.URL)
	}
	if res.Paused && !res.Resumed {
		return nil, fmt.Errorf("cdp %s: the target paused and was never resumed", ep)
	}
	return res, nil
}
