package main

import "fmt"

// Item 199. y72: setDiscoverTargets alone is enough for a target ledger —
// setAutoAttach adds nothing to this output. The navigation a target takes is
// only ever visible as targetInfoChanged; targetCreated carries the blank URL.

func init() {
	registerOp(op{
		name:  "observe_web_session",
		route: "Y",
		desc:  "ledger targetCreated / targetInfoChanged / targetDestroyed events over the collect window",
		needs: true,
		run:   opObserveWebSession,
	})
}

type sessionEvent struct {
	Kind  string `json:"kind"`
	ID    string `json:"target_id"`
	Type  string `json:"type,omitempty"`
	URL   string `json:"url,omitempty"`
	Title string `json:"title,omitempty"`
}

type sessionLedger struct {
	Events    []sessionEvent `json:"events"`
	Created   int            `json:"created"`
	Changed   int            `json:"changed"`
	Destroyed int            `json:"destroyed"`
}

func opObserveWebSession(target string) (any, error) {
	ep, _, err := webTarget(target)
	if err != nil {
		return nil, err
	}
	out, sk, err := webRun("observe_web_session", ep, webSpec{
		Mode:    "session",
		Steps:   []webStep{{Method: "Target.setDiscoverTargets", Params: map[string]any{"discover": true}}},
		Collect: &webCollect{Ms: 1500, Prefixes: []string{"Target.targetCreated", "Target.targetInfoChanged", "Target.targetDestroyed"}},
	})
	if sk != nil {
		return sk, nil
	}
	if err != nil {
		return nil, err
	}
	var res sessionLedger
	for _, e := range out.Events {
		row := sessionEvent{Kind: e.Method}
		switch e.Method {
		case "Target.targetCreated", "Target.targetInfoChanged":
			info, _ := e.Params["targetInfo"].(map[string]any)
			row.ID = str(info["targetId"])
			row.Type = str(info["type"])
			row.URL = str(info["url"])
			row.Title = str(info["title"])
		case "Target.targetDestroyed":
			row.ID = str(e.Params["targetId"])
		default:
			continue
		}
		res.Events = append(res.Events, row)
		switch e.Method {
		case "Target.targetCreated":
			res.Created++
		case "Target.targetInfoChanged":
			res.Changed++
		case "Target.targetDestroyed":
			res.Destroyed++
		}
	}
	if len(out.Steps) == 0 || !out.Steps[0].Ok {
		return nil, fmt.Errorf("cdp %s: Target.setDiscoverTargets: %s", ep, stepFailure(out.Steps, 0))
	}
	return res, nil
}
