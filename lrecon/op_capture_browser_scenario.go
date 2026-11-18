package main

import "fmt"

// Item 182. One page load, captured at the protocol: navigate, let the load
// finish, then read the Network events. §y58 attaches to an app already started
// with --remote-debugging-port=9222.

func init() {
	registerOp(op{
		name:  "capture_browser_scenario",
		route: "Y",
		desc:  "load <endpoint>=<url> in the attached browser and record the request table of that load",
		needs: true,
		run:   opCaptureBrowserScenario,
	})
}

type browserScenario struct {
	Mode     string          `json:"mode"`
	Target   string          `json:"target,omitempty"`
	URL      string          `json:"url"`
	Requests []webRequestRow `json:"requests"`
	Count    int             `json:"count"`
	Loaded   bool            `json:"load_event"`
	Bodies   bool            `json:"bodies"`
}

func opCaptureBrowserScenario(target string) (any, error) {
	ep, arg, err := webTarget(target)
	if err != nil {
		return nil, err
	}
	if arg == "" {
		return nil, fmt.Errorf("no page to load: pass the endpoint and the URL as host:port=<url> (the app must already run with --remote-debugging-port)")
	}
	steps := []webStep{
		{Method: "Network.enable"},
		{Method: "Page.enable"},
		{Method: "Page.setLifecycleEventsEnabled", Params: map[string]any{"enabled": true}},
		{Method: "Page.navigate", Params: map[string]any{"url": arg}},
	}
	out, sk, err := webRun("capture_browser_scenario", ep, webSpec{
		Mode:    "session",
		Steps:   steps,
		Collect: &webCollect{Ms: 1500, Prefixes: []string{"Network.", "Page."}},
	})
	if sk != nil {
		return sk, nil
	}
	if err != nil {
		return nil, err
	}
	res := browserScenario{Mode: "navigate", URL: arg, Requests: captureRequests(out.Events)}
	if out.Target != nil {
		res.Target = out.Target.ID
	}
	res.Count = len(res.Requests)
	for _, e := range out.Events {
		if e.Method == "Page.loadEventFired" {
			res.Loaded = true
		}
	}
	if res.Count == 0 {
		return nil, fmt.Errorf("cdp %s: the load produced no Network.requestWillBeSent events: Network.enable must come before Page.navigate", ep)
	}
	return res, nil
}
