package main

import (
	"fmt"
	"sort"
)

// Item 191. y65: the document's own listeners are not the page's listeners, so
// both window and document objectIds are asked, each with depth:-1 and
// pierce:true, and the answers are merged.

func init() {
	registerOp(op{
		name:  "inspect_web_event_listeners",
		route: "Y",
		desc:  "read window and document event listeners over DOMDebugger, merged per scope",
		needs: true,
		run:   opInspectWebEventListeners,
	})
}

type listenerRow struct {
	Scope      string `json:"scope"`
	Type       string `json:"type"`
	UseCapture bool   `json:"capture"`
	Once       bool   `json:"once"`
	Passive    bool   `json:"passive"`
	Line       int    `json:"line"`
	Column     int    `json:"column"`
}

type listenerReport struct {
	Target    string         `json:"target,omitempty"`
	Listeners []listenerRow  `json:"listeners"`
	ByType    map[string]int `json:"by_type"`
}

func opInspectWebEventListeners(target string) (any, error) {
	ep, _, err := webTarget(target)
	if err != nil {
		return nil, err
	}
	get := func(obj string) webStep {
		return webStep{Method: "DOMDebugger.getEventListeners", Params: map[string]any{"objectId": obj, "depth": -1, "pierce": true}}
	}
	out, sk, err := webRun("inspect_web_event_listeners", ep, webSpec{
		Mode: "session",
		Steps: []webStep{
			{Method: "Runtime.enable"},
			{Method: "Runtime.evaluate", Params: map[string]any{"expression": "window"}},
			{Method: "Runtime.evaluate", Params: map[string]any{"expression": "document"}},
			get("$1.result.objectId"),
			get("$2.result.objectId"),
		},
	})
	if sk != nil {
		return sk, nil
	}
	if err != nil {
		return nil, err
	}
	res := listenerReport{ByType: map[string]int{}}
	if out.Target != nil {
		res.Target = out.Target.ID
	}
	for i, scope := range []string{"window", "document"} {
		step := 3 + i
		if step >= len(out.Steps) || !out.Steps[step].Ok {
			return nil, fmt.Errorf("cdp %s: %s listeners: %s", ep, scope, stepFailure(out.Steps, step))
		}
		arr, _ := out.Steps[step].Result["listeners"].([]any)
		for _, l := range arr {
			m, ok := l.(map[string]any)
			if !ok {
				continue
			}
			row := listenerRow{
				Scope:      scope,
				Type:       str(m["type"]),
				UseCapture: m["useCapture"] == true,
				Once:       m["once"] == true,
				Passive:    m["passive"] == true,
				Line:       int(num(m["lineNumber"])),
				Column:     int(num(m["columnNumber"])),
			}
			res.Listeners = append(res.Listeners, row)
			res.ByType[row.Type]++
		}
	}
	sort.Slice(res.Listeners, func(i, j int) bool {
		if res.Listeners[i].Scope != res.Listeners[j].Scope {
			return res.Listeners[i].Scope < res.Listeners[j].Scope
		}
		if res.Listeners[i].Type != res.Listeners[j].Type {
			return res.Listeners[i].Type < res.Listeners[j].Type
		}
		return res.Listeners[i].Line < res.Listeners[j].Line
	})
	return res, nil
}
