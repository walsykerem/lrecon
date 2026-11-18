package main

import "fmt"

// Item 194. y67: /json/list is returned as it is, every type included. The old
// page|background_page|service_worker whitelist hid real targets (worker,
// shared_worker, browser_ui all show up in practice) and there is no browser/tab
// row in it to filter out.

func init() {
	registerOp(op{
		name:  "list_browser_targets",
		route: "Y",
		desc:  "list every target from /json/list unfiltered, with the browser websocket from /json/version",
		needs: true,
		run:   opListBrowserTargets,
	})
}

type browserTargets struct {
	Browser string         `json:"browser_ws,omitempty"`
	Targets []webTargetRow `json:"targets"`
	Count   int            `json:"count"`
	ByType  map[string]int `json:"by_type"`
}

func opListBrowserTargets(target string) (any, error) {
	ep, _, err := webTarget(target)
	if err != nil {
		return nil, err
	}
	out, sk, err := webRun("list_browser_targets", ep, webSpec{Mode: "list"})
	if sk != nil {
		return sk, nil
	}
	if err != nil {
		return nil, err
	}
	res := browserTargets{Targets: out.Targets, ByType: map[string]int{}}
	res.Count = len(res.Targets)
	for _, t := range res.Targets {
		res.ByType[t.Type]++
	}
	res.Browser = str(out.Version["webSocketDebuggerUrl"])
	if res.Count == 0 {
		return nil, fmt.Errorf("cdp %s: /json/list returned no targets: the app is reachable but has none (JsonListIsEmpty)", ep)
	}
	return res, nil
}
