package main

import "fmt"

// Item 183. §y59 adds no method of its own: an Electron app is a Chromium with
// an extra process plane, so the same Network capture works. lrecon attaches to
// an app the user already started with --remote-debugging-port; it never spawns
// the app, which keeps the "browser is never restarted" rule of §y58.

func init() {
	registerOp(op{
		name:  "capture_electron_scenario",
		route: "Y",
		desc:  "capture the request table of a running Electron renderer over its debugging port",
		needs: true,
		run:   opCaptureElectronScenario,
	})
}

func opCaptureElectronScenario(target string) (any, error) {
	ep, arg, err := webTarget(target)
	if err != nil {
		return nil, err
	}
	spec := webSpec{
		Mode:    "session",
		Steps:   []webStep{{Method: "Network.enable"}, {Method: "Page.enable"}},
		Collect: &webCollect{Ms: 1500, Prefixes: []string{"Network."}},
	}
	if arg != "" {
		spec.Steps = append(spec.Steps,
			webStep{Method: "Page.setLifecycleEventsEnabled", Params: map[string]any{"enabled": true}},
			webStep{Method: "Page.navigate", Params: map[string]any{"url": arg}},
		)
	}
	out, sk, err := webRun("capture_electron_scenario", ep, spec)
	if sk != nil {
		return sk, nil
	}
	if err != nil {
		return nil, err
	}
	res := browserScenario{Mode: "attach", URL: arg, Requests: captureRequests(out.Events)}
	if out.Target != nil {
		res.Target = out.Target.ID
		if arg == "" {
			res.URL = out.Target.URL
		}
	}
	res.Count = len(res.Requests)
	for _, e := range out.Events {
		if e.Method == "Page.loadEventFired" {
			res.Loaded = true
		}
	}
	if res.Count == 0 {
		return nil, fmt.Errorf("cdp %s: no Network.requestWillBeSent events in the collect window: is the renderer idle (pass =<url> to reload it)?", ep)
	}
	return res, nil
}
