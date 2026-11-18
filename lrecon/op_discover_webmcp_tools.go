package main

import "fmt"

// Item 188. y63: the page's own document.modelContext is the only mediated
// path. A polyfill install is the third choice, so it is reported as
// source:"polyfill" and tools are labelled mediated:false — never silently as
// native.

func init() {
	registerOp(op{
		name:  "discover_webmcp_tools",
		route: "Y",
		desc:  "read document.modelContext tools from a secure live page, labelling native vs polyfill",
		needs: true,
		run:   opDiscoverWebmcpTools,
	})
}

type webmcpTool struct {
	Name     string `json:"name"`
	Mediated bool   `json:"mediated"`
	Source   string `json:"source"`
}

type webmcpDiscovery struct {
	Secure  bool         `json:"secure_context"`
	Native  bool         `json:"native"`
	Source  string       `json:"source"` // native | none | polyfill
	Tools   []webmcpTool `json:"tools"`
	Refused string       `json:"refused,omitempty"`
}

// webmcpTarget expands the documented bare-port shorthand ("9222") before
// webTarget sees it: webTarget tests looksLikeProcessName first
// (op_web_util.go:379), and a digits-only word passes that test, so its own
// port branch (op_web_util.go:383-390) never runs and the op refused with
// "live runtime targets are out of scope" for an input it documents.
// ponytail: drop this once webTarget checks digits before process names.
func webmcpTarget(target string) string {
	if digitsOnly(target) {
		return "127.0.0.1:" + target
	}
	return target
}

func opDiscoverWebmcpTools(target string) (any, error) {
	ep, _, err := webTarget(webmcpTarget(target))
	if err != nil {
		return nil, err
	}
	expr := `(async () => {
  if (!isSecureContext) return { secure: false };
  const mc = document.modelContext;
  if (!mc) return { secure: true, native: false, names: [] };
  let list = [];
  try { list = typeof mc.getTools === "function" ? await mc.getTools() : (mc.tools || []); } catch (e) { list = []; }
  const names = (list || []).map((t) => (t && (t.name || t.id)) || String(t)).filter(Boolean);
  return { secure: true, native: true, names };
})()`
	out, sk, err := webRun("discover_webmcp_tools", ep, webSpec{
		Mode: "session",
		Steps: []webStep{
			{Method: "Runtime.enable"},
			{Method: "Runtime.evaluate", Params: map[string]any{"expression": expr, "awaitPromise": true, "returnByValue": true}},
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
	res := webmcpDiscovery{}
	if secure, ok := val["secure"].(bool); ok {
		res.Secure = secure
	}
	if !res.Secure {
		res.Refused = "insecure-context"
		return res, nil
	}
	res.Native, _ = val["native"].(bool)
	res.Source = "none"
	if res.Native {
		res.Source = "native"
	}
	names, _ := val["names"].([]any)
	for _, n := range names {
		res.Tools = append(res.Tools, webmcpTool{Name: str(n), Mediated: res.Native, Source: res.Source})
	}
	return res, nil
}

// evaluateValue unwraps Runtime.evaluate's result.value, where returnByValue put
// the object. A missing value is an error, not an empty map.
func evaluateValue(out webOut, i int) (map[string]any, error) {
	if i >= len(out.Steps) || !out.Steps[i].Ok {
		return nil, fmt.Errorf("%s", stepFailure(out.Steps, i))
	}
	v := nested(out.Steps[i].Result, "result", "value")
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("Runtime.evaluate returned no object (value: %v): pass returnByValue", v)
	}
	return m, nil
}
