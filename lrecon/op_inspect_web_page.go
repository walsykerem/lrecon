package main

import "fmt"

// Item 193. y66: one Runtime.evaluate for the page facts, because
// DOM.getDocument{depth:-1} costs megabytes on a real SPA and Page.getFrameTree
// says nothing about the document itself.

func init() {
	registerOp(op{
		name:  "inspect_web_page",
		route: "Y",
		desc:  "read title, readyState, url, node count, html size and viewport of the attached tab in one evaluate",
		needs: true,
		run:   opInspectWebPage,
	})
}

const pageProbe = `({ title: document.title, readyState: document.readyState,
  href: location.href, html: document.documentElement ? document.documentElement.outerHTML.length : 0,
  nodes: document.querySelectorAll("*").length, w: innerWidth, h: innerHeight,
  ua: navigator.userAgent })`

type pageFacts struct {
	Target     string `json:"target,omitempty"`
	URL        string `json:"url"`
	Title      string `json:"title"`
	ReadyState string `json:"ready_state"`
	Nodes      int    `json:"nodes"`
	HTMLBytes  int    `json:"html_bytes"`
	Width      int    `json:"width"`
	Height     int    `json:"height"`
	UA         string `json:"user_agent"`
}

func opInspectWebPage(target string) (any, error) {
	ep, _, err := webTarget(target)
	if err != nil {
		return nil, err
	}
	out, sk, err := webRun("inspect_web_page", ep, webSpec{
		Mode: "session",
		Steps: []webStep{
			{Method: "Runtime.enable"},
			{Method: "Runtime.evaluate", Params: map[string]any{"expression": pageProbe, "returnByValue": true}},
		},
	})
	if sk != nil {
		return sk, nil
	}
	if err != nil {
		return nil, err
	}
	val, err := evaluateValue(out, 1)
	if err != nil {
		return nil, fmt.Errorf("cdp %s: %v", ep, err)
	}
	res := pageFacts{
		URL:        str(val["href"]),
		Title:      str(val["title"]),
		ReadyState: str(val["readyState"]),
		Nodes:      int(num(val["nodes"])),
		HTMLBytes:  int(num(val["html"])),
		Width:      int(num(val["w"])),
		Height:     int(num(val["h"])),
		UA:         str(val["ua"]),
	}
	if out.Target != nil {
		res.Target = out.Target.ID
	}
	if res.ReadyState == "" {
		return nil, fmt.Errorf("cdp %s: the page probe returned no readyState: Runtime.enable must precede the evaluate", ep)
	}
	return res, nil
}
