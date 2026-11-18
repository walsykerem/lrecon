package main

import (
	"fmt"
	"strings"
)

// Item 198. y71: Runtime, Debugger and Log are all enabled before the page is
// touched, because a domain that is off emits nothing at all — the earlier
// version missed every Log.entryAdded event this way.

func init() {
	registerOp(op{
		name:  "observe_web_execution",
		route: "Y",
		desc:  "enable Runtime/Debugger/Log before navigating, then report console, log and exception entries",
		needs: true,
		run:   opObserveWebExecution,
	})
}

type executionReport struct {
	Target  string        `json:"target,omitempty"`
	URL     string        `json:"url,omitempty"`
	Entries []observation `json:"entries"`
	Since   string        `json:"since"`
	Console int           `json:"console"`
	Logs    int           `json:"logs"`
	Errors  int           `json:"errors"`
}

func opObserveWebExecution(target string) (any, error) {
	ep, arg, err := webTarget(target)
	if err != nil {
		return nil, err
	}
	steps := []webStep{
		{Method: "Runtime.enable"},
		{Method: "Debugger.enable"},
		{Method: "Log.enable"},
		{Method: "Page.enable"},
	}
	if arg != "" {
		steps = append(steps, webStep{Method: "Page.navigate", Params: map[string]any{"url": arg}})
	}
	out, sk, err := webRun("observe_web_execution", ep, webSpec{
		Mode:    "session",
		Steps:   steps,
		Collect: &webCollect{Ms: 1500, Prefixes: []string{"Log.", "Runtime.", "Page."}},
	})
	if sk != nil {
		return sk, nil
	}
	if err != nil {
		return nil, err
	}
	res := executionReport{URL: arg, Since: "enable", Entries: observationsFrom(out.Events, "Runtime.consoleAPICalled", "Runtime.exceptionThrown")}
	if out.Target != nil {
		res.Target = out.Target.ID
		if arg == "" {
			res.URL = out.Target.URL
		}
	}
	for _, e := range out.Events {
		if e.Method != "Log.entryAdded" {
			continue
		}
		entry, _ := e.Params["entry"].(map[string]any)
		res.Entries = append(res.Entries, observation{
			Kind:  "Log.entryAdded/" + str(entry["source"]),
			Level: str(entry["level"]),
			Text:  str(entry["text"]),
			URL:   str(entry["url"]),
			Line:  int(num(entry["lineNumber"])),
		})
	}
	for _, e := range res.Entries {
		switch {
		case e.Kind == "Runtime.consoleAPICalled":
			res.Console++
		case strings.HasPrefix(e.Kind, "Log.entryAdded"):
			res.Logs++
		}
		if e.Level == "error" || e.Kind == "Runtime.exceptionThrown" {
			res.Errors++
		}
	}
	if len(res.Entries) == 0 {
		// Runtime/Debugger/Log are enabled before the navigation (see the steps
		// above), so an empty window is the page's answer, not a call order
		// mistake: say that instead of pointing at a fix already in place.
		return nil, fmt.Errorf("cdp %s: no console, log or exception entries in the 1.5s window after Runtime/Debugger/Log enable: a page that logs nothing reports nothing", ep)
	}
	return res, nil
}
