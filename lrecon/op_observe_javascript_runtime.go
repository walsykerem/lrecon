package main

import (
	"fmt"
	"strings"
)

// Item 197. y70 owns the attach contract and y71 owns the observation body. The
// attach here is the driver's own session (flattened by the WebSocket), so the
// only extra call is Runtime/Debugger enable before anything runs.

func init() {
	registerOp(op{
		name:  "observe_javascript_runtime",
		route: "Y",
		desc:  "attach to the page and report Runtime/Debugger observations from the collect window",
		needs: true,
		run:   opObserveJavascriptRuntime,
	})
}

type runtimeObservation struct {
	Source       string        `json:"source"`
	Target       string        `json:"target,omitempty"`
	Sessions     int           `json:"sessions_attached"`
	Seen         int           `json:"targets_seen"`
	Observations []observation `json:"observations"`
	Since        string        `json:"since"`
}

type observation struct {
	Kind  string `json:"kind"`
	Text  string `json:"text"`
	URL   string `json:"url,omitempty"`
	Line  int    `json:"line,omitempty"`
	Level string `json:"level,omitempty"`
}

func opObserveJavascriptRuntime(target string) (any, error) {
	if strings.HasPrefix(strings.TrimSpace(target), "frida:") {
		// An in-process attach is a live session; the same question about page
		// JavaScript is answered over CDP, which is the half this op keeps.
		refuseKind(kindOutOfScope, javascriptRuntimeFridaDecline)
	}
	ep, _, err := webTarget(target)
	if err != nil {
		return nil, err
	}
	out, sk, err := webRun("observe_javascript_runtime", ep, webSpec{
		Mode: "session",
		Steps: []webStep{
			{Method: "Runtime.enable"},
			{Method: "Debugger.enable"},
		},
		Collect: &webCollect{Ms: 1000, Prefixes: []string{"Runtime.", "Debugger."}},
	})
	if sk != nil {
		return sk, nil
	}
	if err != nil {
		return nil, err
	}
	res := runtimeObservation{Source: "y71", Seen: len(out.Targets), Since: "attach"}
	if out.Target != nil {
		res.Target = out.Target.ID
		res.Sessions = 1
	}
	res.Observations = observationsFrom(out.Events, "Debugger.scriptParsed", "Runtime.consoleAPICalled", "Runtime.exceptionThrown")
	if len(res.Observations) == 0 && res.Sessions > 0 {
		// The window is 1s and both domains are enabled before it opens: an
		// empty observation is the page being quiet, not a missed event.
		return nil, fmt.Errorf("cdp %s: attached to %s but saw no Runtime/Debugger events in the 1s window: a page that runs nothing reports nothing (no_observations)", ep, res.Target)
	}
	return res, nil
}

// observationsFrom keeps only the event kinds asked for, so an item's output
// does not depend on whatever else the page happened to emit.
func observationsFrom(events []webEvent, kinds ...string) []observation {
	want := map[string]bool{}
	for _, k := range kinds {
		want[k] = true
	}
	var out []observation
	for _, e := range events {
		if !want[e.Method] {
			continue
		}
		row := observation{Kind: e.Method}
		switch e.Method {
		case "Debugger.scriptParsed":
			row.URL = str(e.Params["url"])
			row.Line = int(num(e.Params["startLine"]))
		case "Runtime.consoleAPICalled":
			row.Level = str(e.Params["type"])
			row.Text = argText(e.Params["args"])
		case "Runtime.exceptionThrown":
			det, _ := e.Params["exceptionDetails"].(map[string]any)
			row.Text = str(det["text"])
			row.URL = str(det["url"])
			row.Line = int(num(det["lineNumber"]))
		}
		out = append(out, row)
	}
	return out
}

// argText joins console arguments by their value or description; a remote object
// carries one or the other depending on its type.
func argText(v any) string {
	arr, _ := v.([]any)
	var s strings.Builder
	for i, a := range arr {
		m, _ := a.(map[string]any)
		part := str(m["value"])
		if part == "" {
			part = str(m["description"])
		}
		if i > 0 {
			s.WriteString(" ")
		}
		s.WriteString(part)
	}
	return s.String()
}
