package main

import "fmt"

// Item 196. y69: list, never attach. TargetInfo.type is a free string in the
// protocol, so no whitelist is applied and none could be. A reachable browser
// with zero targets is an error, not an empty list.

func init() {
	registerOp(op{
		name:  "list_javascript_runtime_targets",
		route: "Y",
		desc:  "list Target.getTargets unfiltered (id, type, title, url, attached) without attaching to any of them",
		needs: true,
		run:   opListJavascriptRuntimeTargets,
	})
}

type runtimeTarget struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Title    string `json:"title"`
	URL      string `json:"url"`
	Attached bool   `json:"attached"`
}

type runtimeTargets struct {
	Targets []runtimeTarget `json:"targets"`
	Count   int             `json:"count"`
}

func opListJavascriptRuntimeTargets(target string) (any, error) {
	ep, _, err := webTarget(target)
	if err != nil {
		return nil, err
	}
	out, sk, err := webRun("list_javascript_runtime_targets", ep, webSpec{
		Mode:  "session",
		Steps: []webStep{{Method: "Target.getTargets"}},
	})
	if sk != nil {
		return sk, nil
	}
	if err != nil {
		return nil, err
	}
	if len(out.Steps) == 0 || !out.Steps[0].Ok {
		return nil, fmt.Errorf("cdp %s: Target.getTargets: %s", ep, stepFailure(out.Steps, 0))
	}
	infos, _ := out.Steps[0].Result["targetInfos"].([]any)
	res := runtimeTargets{}
	for _, v := range infos {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		res.Targets = append(res.Targets, runtimeTarget{
			ID:       str(m["targetId"]),
			Type:     str(m["type"]),
			Title:    str(m["title"]),
			URL:      str(m["url"]),
			Attached: m["attached"] == true,
		})
	}
	res.Count = len(res.Targets)
	if res.Count == 0 {
		// A live endpoint with nothing to list is a missing process plane, not an
		// lrecon fault: the phrasing keeps classify off kindInternal.
		return nil, fmt.Errorf("cdp %s: the browser answered but reported no targets: no live process to list (no_targets)", ep)
	}
	return res, nil
}
