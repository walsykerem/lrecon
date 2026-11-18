package main

import (
	"fmt"
	"regexp"
)

// Item 190. y64 folds into y66's single Runtime.evaluate: an Electron renderer
// is a page, and its version is in the UA. process.versions is absent under
// contextIsolation, so the UA is the only cheap read here.

func init() {
	registerOp(op{
		name:  "inspect_electron_page",
		route: "Y",
		desc:  "evaluate one expression in the attached page and report the Electron version the UA names",
		needs: true,
		run:   opInspectElectronPage,
	})
}

var electronUARe = regexp.MustCompile(`Electron/([0-9][0-9.]*)`)

type electronPage struct {
	Expression string `json:"expression"`
	Type       string `json:"type"`
	Value      any    `json:"value"`
	UA         string `json:"user_agent"`
	Electron   string `json:"electron_version,omitempty"`
	Chrome     string `json:"chrome_version,omitempty"`
	Error      string `json:"exception,omitempty"`
}

func opInspectElectronPage(target string) (any, error) {
	ep, expr, err := webTarget(target)
	if err != nil {
		return nil, err
	}
	if expr == "" {
		expr = "typeof process !== 'undefined' ? process.type || 'process' : 'no-process'"
	}
	out, sk, err := webRun("inspect_electron_page", ep, webSpec{
		Mode: "session",
		Steps: []webStep{
			{Method: "Runtime.enable"},
			{Method: "Runtime.evaluate", Params: map[string]any{"expression": expr, "returnByValue": true, "awaitPromise": true}},
			{Method: "Runtime.evaluate", Params: map[string]any{"expression": "navigator.userAgent", "returnByValue": true}},
		},
	})
	if sk != nil {
		return sk, nil
	}
	if err != nil {
		return nil, err
	}
	res := electronPage{Expression: expr}
	// Both evaluates are part of the fixed spec, so a failed or missing step is
	// an error: reporting a page with no UA would hide the only version source.
	ua, err := out.step(2)
	if err != nil {
		return nil, fmt.Errorf("cdp %s: %w", ep, err)
	}
	res.UA = str(nested(ua, "result", "value"))
	if m := electronUARe.FindStringSubmatch(res.UA); m != nil {
		res.Electron = m[1]
	}
	if m := chromeUARe.FindStringSubmatch(res.UA); m != nil {
		res.Chrome = m[1]
	}
	stepResult, err := out.step(1)
	if err != nil {
		return nil, fmt.Errorf("cdp %s: %w", ep, err)
	}
	if exc := nested(stepResult, "exceptionDetails"); exc != nil {
		res.Error = str(nested(exc, "text"))
	}
	if v := nested(stepResult, "result"); v != nil {
		res.Type = str(nested(v, "type"))
		res.Value = nested(v, "value")
	}
	return res, nil
}

var chromeUARe = regexp.MustCompile(`Chrome/([0-9][0-9.]*)`)
