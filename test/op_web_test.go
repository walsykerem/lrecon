package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Every WEB item of final.md, with the route its row carries.
var webItems = []struct{ name, route string }{
	{"analyze_javascript_application", "L"},
	{"analyze_web_bundle", "L"},
	{"capture_browser_scenario", "Y"},
	{"capture_electron_scenario", "Y"},
	{"capture_web_screenshot", "Y"},
	{"compare_javascript_export_shapes", "L"},
	{"compare_web_captures", "Y"},
	{"compare_web_screenshots", "Y"},
	{"discover_webmcp_tools", "Y"},
	{"export_web_scripts", "L"},
	{"inspect_electron_page", "Y"},
	{"inspect_web_event_listeners", "Y"},
	{"inspect_web_network_capture", "L"},
	{"inspect_web_page", "Y"},
	{"list_browser_targets", "Y"},
	{"list_electron_targets", "Y"},
	{"list_javascript_runtime_targets", "Y"},
	{"observe_javascript_runtime", "Y"},
	{"observe_web_execution", "Y"},
	{"observe_web_session", "Y"},
	{"reconcile_javascript_runtime", "Y"},
	{"recover_javascript_sources", "L"},
	{"trace_javascript_semantics", "Y"},
	{"trace_web_module_imports", "L"},
	{"trace_web_source_location", "L"},
}

func TestWebItemsRegistered(t *testing.T) {
	for _, it := range webItems {
		o, ok := ops[it.name]
		if !ok {
			t.Errorf("%s: not registered", it.name)
			continue
		}
		if o.route != it.route {
			t.Errorf("%s: route %q, want %q", it.name, o.route, it.route)
		}
		if !o.needs {
			t.Errorf("%s: every WEB item takes a target", it.name)
		}
	}
}

// fields re-marshals a result so a test asserts exactly what a caller would see.
func fields(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}

func run(t *testing.T, name, target string) any {
	t.Helper()
	v, err := runOp(name, target)
	if err != nil {
		t.Fatalf("%s %s: %v", name, target, err)
	}
	return v
}

// numList flattens a JSON array; a nil slice marshals to null and counts as empty.
func numList(t *testing.T, v any) []string {
	t.Helper()
	if v == nil {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		t.Fatalf("want a JSON array, got %T", v)
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		out = append(out, fmt.Sprint(x))
	}
	return out
}

// The fixture every static JS item reads: one real edge of each kind, one edge
// that only exists inside a comment, one regex, one template, one export each.
const webJSSrc = `// require("./ghost.js") must never become an edge
import a from "./a.js";
import { b } from "./b.js";
const fs = require('node:fs');
const dyn = import("./dyn.js");
const re = /ab\/c/g;
export function alpha(x, y) {}
export const beta = (p) => p;
module.exports.gamma = function (q) {};
const tpl = ` + "`" + `hi ${a} there` + "`" + `;
`

func TestAnalyzeJavascriptApplication(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "app.js")
	if err := os.WriteFile(src, []byte(webJSSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	f := fields(t, run(t, "analyze_javascript_application", src))
	if f["bytes"] != float64(len(webJSSrc)) {
		t.Errorf("bytes %v, want %d", f["bytes"], len(webJSSrc))
	}
	if f["comments"] != float64(1) || f["regex_literals"] != float64(1) || f["templates"] != float64(1) {
		t.Errorf("comments/regex/templates = %v/%v/%v, want 1/1/1", f["comments"], f["regex_literals"], f["templates"])
	}
	if f["truncated"] != false {
		t.Errorf("truncated %v, want false", f["truncated"])
	}
	var specs []string
	for _, e := range f["imports"].([]any) {
		m := e.(map[string]any)
		specs = append(specs, fmt.Sprint(m["spec"]))
	}
	want := []string{"./a.js", "./b.js", "node:fs", "./dyn.js"}
	if !reflect.DeepEqual(specs, want) {
		t.Errorf("imports %v, want %v (source order, comment excluded)", specs, want)
	}
	if have := numList(t, f["exports"]); !reflect.DeepEqual(have, []string{"alpha", "beta", "gamma"}) {
		t.Errorf("exports %v", have)
	}
	// The commented require is a comment, not a string: it must appear nowhere.
	// The template's text is a real string and must.
	if containsStr(numList(t, f["strings"]), "./ghost.js") {
		t.Errorf("string table %v picked up comment text", f["strings"])
	}
	if !containsStr(numList(t, f["strings"]), "hi  there") {
		t.Errorf("string table %v lost the template literal", f["strings"])
	}
}

func TestAnalyzeWebBundle(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bundle.js")
	if err := os.WriteFile(p, []byte(webJSSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	f := fields(t, run(t, "analyze_web_bundle", p))
	if f["count"] != float64(4) || f["modules"] != float64(4) {
		t.Errorf("count/modules %v/%v, want 4/4", f["count"], f["modules"])
	}
	graph := f["graph"].(map[string]any)
	deps := numList(t, graph["bundle.js"])
	want := []string{"./a.js", "./b.js", "./dyn.js", "node:fs"}
	if !reflect.DeepEqual(deps, want) {
		t.Errorf("graph %v, want %v", deps, want)
	}
	if containsStr(deps, "./ghost.js") {
		t.Error("the commented require became a dependency")
	}
}

func TestCompareJavascriptExportShapes(t *testing.T) {
	dir := t.TempDir()
	oldSrc := "exports.alpha = function (x, y) {};\nexports.gamma = function (q) {};\n"
	newSrc := "exports.alpha = function (x, y, z) {};\nexports.delta = function () {};\n"
	for name, body := range map[string]string{"old.js": oldSrc, "new.js": newSrc} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f := fields(t, run(t, "compare_javascript_export_shapes", dir))
	if f["old"] != "new.js" && f["old"] != "old.js" {
		t.Fatalf("old %v", f["old"])
	}
	added := f["added"].([]any)
	if len(added) != 1 || added[0].(map[string]any)["name"] != "delta" {
		t.Errorf("added %v, want [delta]", added)
	}
	removed := f["removed"].([]any)
	if len(removed) != 1 || removed[0].(map[string]any)["name"] != "gamma" {
		t.Errorf("removed %v, want [gamma]", removed)
	}
	changed := f["changed"].([]any)
	if len(changed) != 1 {
		t.Fatalf("changed %v, want one arity change", changed)
	}
	c := changed[0].(map[string]any)
	if c["name"] != "alpha" || c["from"] != float64(2) || c["to"] != float64(3) {
		t.Errorf("changed %v, want alpha 2->3", c)
	}
}

func TestExportWebScripts(t *testing.T) {
	dir := t.TempDir()
	archive := writeAsarArchive(t, dir, "app.asar", map[string][]byte{
		"index.html":          []byte("<html></html>"),
		"main.js":             []byte("module.exports = 1;\n"),
		"node_modules/x/y.js": []byte("exports.y = function (a) {};\n"),
	})
	f := fields(t, run(t, "export_web_scripts", archive))
	if f["written"] != float64(2) {
		t.Errorf("written %v, want 2 (html is not a script)", f["written"])
	}
	scripts := numList(t, f["scripts"])
	if !reflect.DeepEqual(scripts, []string{"main.js", "node_modules/x/y.js"}) {
		t.Errorf("scripts %v", scripts)
	}
	body, err := os.ReadFile(filepath.Join(archive+".scripts", "node_modules/x/y.js"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "exports.y = function (a) {};\n" {
		t.Errorf("extracted body %q", body)
	}
}

func TestInspectWebNetworkCapture(t *testing.T) {
	dir := t.TempDir()
	har := `{"log":{"version":"1.2","creator":{"name":"Chrome","version":"141"},
 "entries":[
  {"request":{"method":"GET","url":"https://api.example.com/v1/x"},"response":{"status":200,"content":{"size":100,"mimeType":"application/json"},"bodySize":80},"time":12.5},
  {"request":{"method":"POST","url":"https://cdn.example.com/y.js"},"response":{"status":404,"content":{"size":0,"mimeType":"text/javascript"},"bodySize":0},"time":2.5}]}}`
	p := filepath.Join(dir, "cap.har")
	if err := os.WriteFile(p, []byte(har), 0o644); err != nil {
		t.Fatal(err)
	}
	f := fields(t, run(t, "inspect_web_network_capture", p))
	if f["version"] != "1.2" || f["creator"] != "Chrome 141" {
		t.Errorf("version/creator %v/%v", f["version"], f["creator"])
	}
	if f["entries"] != float64(2) || f["total_ms"] != float64(15) {
		t.Errorf("entries/total_ms %v/%v, want 2/15", f["entries"], f["total_ms"])
	}
	if hosts := numList(t, f["hosts"]); !reflect.DeepEqual(hosts, []string{"api.example.com", "cdn.example.com"}) {
		t.Errorf("hosts %v", hosts)
	}
	req := f["requests"].([]any)[0].(map[string]any)
	if req["method"] != "GET" || req["status"] != float64(200) || req["bytes"] != float64(100) {
		t.Errorf("first request %v", req)
	}
}

// one map line, two segments: (col 0) -> src/a.ts:1:0 and (col 10) -> src/a.ts:1:10;
// U is base64 index 20, so its VLQ value is 20>>1 = +10.
const webMappings = "AAAA,UAAU"

func TestTraceWebSourceLocation(t *testing.T) {
	dir := t.TempDir()
	sm := fmt.Sprintf(`{"version":3,"sources":["src/a.ts"],"names":[],"mappings":%q}`, webMappings)
	if err := os.WriteFile(filepath.Join(dir, "a.js"), []byte("x;y;\n//# sourceMappingURL=a.js.map\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.js.map"), []byte(sm), 0o644); err != nil {
		t.Fatal(err)
	}
	f := fields(t, run(t, "trace_web_source_location", filepath.Join(dir, "a.js")))
	if f["version"] != float64(3) || f["segments"] != float64(2) {
		t.Fatalf("version/segments %v/%v, want 3/2", f["version"], f["segments"])
	}
	if srcs := numList(t, f["sources"]); !reflect.DeepEqual(srcs, []string{"src/a.ts"}) {
		t.Errorf("sources %v", srcs)
	}
	rows := f["rows"].([]any)
	if len(rows) != 2 {
		t.Fatalf("rows %v", rows)
	}
	first := rows[0].(map[string]any)
	if first["generated_line"] != float64(1) || first["generated_column"] != float64(0) ||
		first["original_line"] != float64(1) || first["original_column"] != float64(0) || first["source"] != "src/a.ts" {
		t.Errorf("row 0 %v", first)
	}
	second := rows[1].(map[string]any)
	if second["generated_column"] != float64(10) || second["original_column"] != float64(10) {
		t.Errorf("row 1 %v, want column 10 (UAAU)", second)
	}
	if got := f["segments_per_source"].(map[string]any)["src/a.ts"]; got != float64(2) {
		t.Errorf("segments_per_source %v", f["segments_per_source"])
	}
}

func TestRecoverJavascriptSources(t *testing.T) {
	dir := t.TempDir()
	orig := "export const a = 1;\n"
	sm := fmt.Sprintf(`{"version":3,"sources":["web/a.ts"],"sourcesContent":[%q],"names":[],"mappings":"AAAA"}`, orig)
	p := filepath.Join(dir, "a.js")
	if err := os.WriteFile(p, []byte("//# sourceMappingURL=a.map\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.map"), []byte(sm), 0o644); err != nil {
		t.Fatal(err)
	}
	f := fields(t, run(t, "recover_javascript_sources", p))
	if f["sources"] != float64(1) || f["bytes"] != float64(len(orig)) {
		t.Errorf("sources/bytes %v/%v", f["sources"], f["bytes"])
	}
	if got := numList(t, f["recovered"]); !reflect.DeepEqual(got, []string{"web/a.ts"}) {
		t.Errorf("recovered %v", got)
	}
	body, err := os.ReadFile(filepath.Join(p+".sources", "web/a.ts"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != orig {
		t.Errorf("recovered body %q", body)
	}
}

func TestTraceWebModuleImports(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"entry.js":    "import \"./top.js\";\nimport \"./lib/util.js\";\nconst fs = require('node:fs');\n",
		"top.js":      "export const t = (a) => a;\n",
		"lib/util.js": "module.exports.u = function () {};\n",
	}
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f := fields(t, run(t, "trace_web_module_imports", filepath.Join(dir, "entry.js")))
	if f["read"] != float64(3) {
		t.Errorf("read %v, want 3 (entry, top, util)", f["read"])
	}
	if len(numList(t, f["external"])) != 1 || numList(t, f["external"])[0] != "node:fs" {
		t.Errorf("external %v, want [node:fs]", f["external"])
	}
	if len(numList(t, f["missing"])) != 0 {
		t.Errorf("missing %v, want none", f["missing"])
	}
	edges := f["edges"].(map[string]any)["entry.js"].([]any)
	if len(edges) != 3 {
		t.Fatalf("entry edges %v", edges)
	}
	e := edges[0].(map[string]any)
	if e["spec"] != "./top.js" || e["status"] != "read" || e["resolved"] != "top.js" {
		t.Errorf("first edge %v", e)
	}
}

// --- runtime items: the transport is a seam, so the op layer runs without a
// browser: canned driver output in, the op's JSON out ---

// fakeDriver answers every CDP call with out. No socket, no browser: the
// boundary under test is the Go side of the driver contract (cdp.go).
func fakeDriver(t *testing.T, out webOut) {
	t.Helper()
	prev := webTransport
	webTransport = func(context.Context, webSpec) (webOut, error) { return out, nil }
	t.Cleanup(func() { webTransport = prev })
}

func okStep(method string, result map[string]any) webStepResult {
	return webStepResult{Method: method, Ok: true, Result: result}
}

func event(method string, params map[string]any) webEvent {
	return webEvent{Method: method, Params: params}
}

func pngBytes(t *testing.T, c color.Color) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	for y := range 2 {
		for x := range 2 {
			img.Set(x, y, c)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func TestWebRuntimeItems(t *testing.T) {
	targets := []webTargetRow{{ID: "T1", Type: "page", Title: "App", URL: "file:///Applications/App.app/Contents/Resources/app.asar/index.html", WS: "ws://127.0.0.1:9222/devtools/page/T1"}}
	reqs := []webEvent{
		event("Network.requestWillBeSent", map[string]any{"requestId": "r1", "request": map[string]any{"method": "GET", "url": "https://api.example.com/x"}}),
		event("Network.responseReceived", map[string]any{"requestId": "r1", "response": map[string]any{"status": float64(200), "mimeType": "application/json"}}),
		event("Page.loadEventFired", map[string]any{"timestamp": float64(1)}),
	}
	shot := pngBytes(t, color.RGBA{R: 10, G: 20, B: 30, A: 255})
	shot2 := pngBytes(t, color.RGBA{R: 200, G: 20, B: 30, A: 255})

	cases := []struct {
		name   string
		target string
		out    webOut
		want   map[string]any
	}{
		{
			name: "list_browser_targets", target: "127.0.0.1:9222",
			out:  webOut{Targets: targets, Version: map[string]any{"webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/browser/B1"}},
			want: map[string]any{"count": float64(1), "browser_ws": "ws://127.0.0.1:9222/devtools/browser/B1"},
		},
		{
			name: "list_javascript_runtime_targets", target: "127.0.0.1:9222",
			out: webOut{Targets: targets, Steps: []webStepResult{okStep("Target.getTargets", map[string]any{"targetInfos": []any{
				map[string]any{"targetId": "T1", "type": "page", "title": "App", "url": "file:///a/index.html", "attached": true},
				map[string]any{"targetId": "T2", "type": "service_worker", "title": "sw", "url": "file:///a/sw.js"},
			}})}},
			want: map[string]any{"count": float64(2), "targets.#": 2},
		},
		{
			name: "inspect_web_page", target: "127.0.0.1:9222",
			out: webOut{Target: &targets[0], Steps: []webStepResult{
				okStep("Runtime.enable", map[string]any{}),
				okStep("Runtime.evaluate", map[string]any{"result": map[string]any{"type": "object", "value": map[string]any{
					"title": "App", "readyState": "complete", "href": "file:///a/index.html",
					"html": float64(4096), "nodes": float64(120), "w": float64(1280), "h": float64(720), "ua": "Mozilla/5.0 Chrome/141.0.0.0",
				}}}),
			}},
			want: map[string]any{"url": "file:///a/index.html", "title": "App", "ready_state": "complete", "nodes": float64(120), "html_bytes": float64(4096), "width": float64(1280), "height": float64(720), "target": "T1"},
		},
		{
			name: "inspect_electron_page", target: "127.0.0.1:9222",
			out: webOut{Steps: []webStepResult{
				okStep("Runtime.enable", map[string]any{}),
				okStep("Runtime.evaluate", map[string]any{"result": map[string]any{"type": "string", "value": "renderer"}}),
				okStep("Runtime.evaluate", map[string]any{"result": map[string]any{"type": "string", "value": "Mozilla/5.0 Chrome/130.0.0.0 Electron/33.2.1 Safari/537.36"}}),
			}},
			want: map[string]any{"type": "string", "value": "renderer", "electron_version": "33.2.1", "chrome_version": "130.0.0.0"},
		},
		{
			name: "inspect_web_event_listeners", target: "127.0.0.1:9222",
			out: webOut{Target: &targets[0], Steps: []webStepResult{
				okStep("Runtime.enable", map[string]any{}),
				okStep("Runtime.evaluate", map[string]any{"result": map[string]any{"objectId": "1"}}),
				okStep("Runtime.evaluate", map[string]any{"result": map[string]any{"objectId": "2"}}),
				okStep("DOMDebugger.getEventListeners", map[string]any{"listeners": []any{
					map[string]any{"type": "click", "useCapture": false, "lineNumber": float64(10), "columnNumber": float64(4)},
				}}),
				okStep("DOMDebugger.getEventListeners", map[string]any{"listeners": []any{
					map[string]any{"type": "click", "useCapture": true, "once": true, "lineNumber": float64(3), "columnNumber": float64(0)},
				}}),
			}},
			want: map[string]any{"by_type": map[string]any{"click": float64(2)}, "listeners.#": 2},
		},
		{
			name: "discover_webmcp_tools", target: "127.0.0.1:9222",
			out: webOut{Steps: []webStepResult{
				okStep("Runtime.enable", map[string]any{}),
				okStep("Runtime.evaluate", map[string]any{"result": map[string]any{"value": map[string]any{
					"secure": true, "native": true, "names": []any{"search", "open"},
				}}}),
			}},
			want: map[string]any{"secure_context": true, "native": true, "source": "native", "tools.#": 2},
		},
		{
			name: "capture_browser_scenario", target: "127.0.0.1:9222=https://app.example.com/",
			out: webOut{Target: &targets[0], Events: reqs, Steps: []webStepResult{
				okStep("Network.enable", map[string]any{}), okStep("Page.enable", map[string]any{}),
				okStep("Page.setLifecycleEventsEnabled", map[string]any{}), okStep("Page.navigate", map[string]any{}),
			}},
			want: map[string]any{"count": float64(1), "load_event": true, "bodies": false, "url": "https://app.example.com/"},
		},
		{
			name: "capture_electron_scenario", target: "127.0.0.1:9222",
			out:  webOut{Target: &targets[0], Events: reqs, Steps: []webStepResult{okStep("Network.enable", map[string]any{}), okStep("Page.enable", map[string]any{})}},
			want: map[string]any{"count": float64(1), "mode": "attach", "url": "file:///Applications/App.app/Contents/Resources/app.asar/index.html"},
		},
		{
			name: "observe_javascript_runtime", target: "127.0.0.1:9222",
			out: webOut{Target: &targets[0], Steps: []webStepResult{okStep("Runtime.enable", map[string]any{}), okStep("Debugger.enable", map[string]any{})}, Events: []webEvent{
				event("Debugger.scriptParsed", map[string]any{"scriptId": "5", "url": "file:///a/main.js", "startLine": float64(0)}),
				event("Runtime.consoleAPICalled", map[string]any{"type": "log", "args": []any{map[string]any{"value": "hello"}}}),
			}},
			want: map[string]any{"sessions_attached": float64(1), "observations.#": 2, "target": "T1"},
		},
		{
			name: "observe_web_execution", target: "127.0.0.1:9222=https://app.example.com/",
			out: webOut{Target: &targets[0], Steps: []webStepResult{
				okStep("Runtime.enable", map[string]any{}), okStep("Debugger.enable", map[string]any{}),
				okStep("Log.enable", map[string]any{}), okStep("Page.enable", map[string]any{}), okStep("Page.navigate", map[string]any{}),
			}, Events: []webEvent{
				event("Runtime.consoleAPICalled", map[string]any{"type": "log", "args": []any{map[string]any{"value": "hi"}}}),
				event("Log.entryAdded", map[string]any{"entry": map[string]any{"source": "network", "level": "error", "text": "404", "url": "https://app.example.com/x"}}),
			}},
			want: map[string]any{"console": float64(1), "logs": float64(1), "errors": float64(1), "entries.#": 2},
		},
		{
			name: "observe_web_session", target: "127.0.0.1:9222",
			out: webOut{Steps: []webStepResult{okStep("Target.setDiscoverTargets", map[string]any{})}, Events: []webEvent{
				event("Target.targetCreated", map[string]any{"targetInfo": map[string]any{"targetId": "T9", "type": "page", "url": ""}}),
				event("Target.targetInfoChanged", map[string]any{"targetInfo": map[string]any{"targetId": "T9", "type": "page", "url": "https://app.example.com/"}}),
				event("Target.targetDestroyed", map[string]any{"targetId": "T9"}),
			}},
			want: map[string]any{"created": float64(1), "changed": float64(1), "destroyed": float64(1), "events.#": 3},
		},
		{
			name: "trace_javascript_semantics", target: "127.0.0.1:9222=42",
			out: webOut{Target: &targets[0], Resumed: true, Steps: []webStepResult{
				okStep("Debugger.enable", map[string]any{}),
				okStep("Debugger.setBreakpointByUrl", map[string]any{"breakpointId": "1:42:0:file:///a/index.html", "locations": []any{
					map[string]any{"scriptId": "5", "lineNumber": float64(41), "columnNumber": float64(0)},
				}}),
				okStep("Debugger.setPauseOnExceptions", map[string]any{}),
			}},
			want: map[string]any{"line": float64(42), "breakpoint_id": "1:42:0:file:///a/index.html", "paused": false, "resumed": true, "locations.#": 1},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fakeDriver(t, c.out)
			f := fields(t, run(t, c.name, c.target))
			for k, want := range c.want {
				if before, ok := strings.CutSuffix(k, ".#"); ok {
					arr, ok := f[before].([]any)
					if !ok || len(arr) != int(want.(int)) {
						t.Errorf("%s: %v, want %d entries", strings.TrimSuffix(k, ".#"), f[strings.TrimSuffix(k, ".#")], want)
					}
					continue
				}
				if !reflect.DeepEqual(f[k], want) {
					t.Errorf("%s = %v, want %v", k, f[k], want)
				}
			}
		})
	}

	// The two items whose output is a file or a pixel diff, checked separately.
	t.Run("capture_web_screenshot", func(t *testing.T) {
		fakeDriver(t, webOut{Target: &targets[0], Steps: []webStepResult{
			okStep("Page.enable", map[string]any{}),
			okStep("Page.captureScreenshot", map[string]any{"data": shot}),
		}})
		dst := filepath.Join(t.TempDir(), "shot.png")
		f := fields(t, run(t, "capture_web_screenshot", "127.0.0.1:9222="+dst))
		if f["width"] != float64(2) || f["height"] != float64(2) || f["target"] != "T1" {
			t.Errorf("screenshot %v", f)
		}
		onDisk, err := os.ReadFile(dst)
		if err != nil {
			t.Fatal(err)
		}
		if f["bytes"] != float64(len(onDisk)) {
			t.Errorf("bytes %v, on disk %d", f["bytes"], len(onDisk))
		}
		raw, err := base64.StdEncoding.DecodeString(shot)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if f["sha256"] != hex.EncodeToString(sum[:]) {
			t.Errorf("sha256 %v, want %x", f["sha256"], sum)
		}
	})

	t.Run("compare_web_screenshots", func(t *testing.T) {
		fakeDriver(t, webOut{Steps: []webStepResult{
			okStep("Page.enable", map[string]any{}),
			okStep("Runtime.evaluate", map[string]any{"result": map[string]any{"value": map[string]any{"x": float64(1), "y": float64(1)}}}),
			okStep("Page.captureScreenshot", map[string]any{"data": shot}),
			okStep("Input.dispatchMouseEvent", map[string]any{}),
			okStep("Input.dispatchMouseEvent", map[string]any{}),
			okStep("Page.captureScreenshot", map[string]any{"data": shot2}),
		}})
		f := fields(t, run(t, "compare_web_screenshots", "127.0.0.1:9222"))
		if f["different_pixels"] != float64(4) || f["total_pixels"] != float64(4) {
			t.Errorf("diff %v, want all 4 pixels changed", f)
		}
		box := f["box"].(map[string]any)
		if box["x0"] != float64(0) || box["y0"] != float64(0) || box["x1"] != float64(1) || box["y1"] != float64(1) {
			t.Errorf("box %v", box)
		}
	})

	t.Run("compare_web_captures", func(t *testing.T) {
		dir := t.TempDir()
		prior := browserScenario{Mode: "attach", Requests: []webRequestRow{
			{Method: "GET", URL: "https://api.example.com/gone", Status: 200},
			{Method: "GET", URL: "https://api.example.com/x", Status: 200},
		}, Count: 2}
		if err := writeJSONFile(filepath.Join(dir, "capture-1.json"), prior); err != nil {
			t.Fatal(err)
		}
		fakeDriver(t, webOut{Events: []webEvent{
			event("Network.requestWillBeSent", map[string]any{"requestId": "r1", "request": map[string]any{"method": "GET", "url": "https://api.example.com/x"}}),
			event("Network.responseReceived", map[string]any{"requestId": "r1", "response": map[string]any{"status": float64(200), "mimeType": "application/json"}}),
			event("Network.requestWillBeSent", map[string]any{"requestId": "r2", "request": map[string]any{"method": "POST", "url": "https://api.example.com/new"}}),
			event("Network.responseReceived", map[string]any{"requestId": "r2", "response": map[string]any{"status": float64(201), "mimeType": "application/json"}}),
		}, Steps: []webStepResult{okStep("Network.enable", map[string]any{}), okStep("Page.enable", map[string]any{})}})
		f := fields(t, run(t, "compare_web_captures", "127.0.0.1:9222="+dir))
		if f["same"] != float64(1) || f["bodies"] != false {
			t.Errorf("diff %v", f)
		}
		if got := numList(t, f["added"]); !reflect.DeepEqual(got, []string{"POST https://api.example.com/new 201"}) {
			t.Errorf("added %v", got)
		}
		if got := numList(t, f["removed"]); !reflect.DeepEqual(got, []string{"GET https://api.example.com/gone 200"}) {
			t.Errorf("removed %v", got)
		}
		if f["before"] != "capture-1.json" || f["after"] != "capture-2.json" {
			t.Errorf("before/after %v/%v", f["before"], f["after"])
		}
	})

	t.Run("reconcile_javascript_runtime", func(t *testing.T) {
		bundle := filepath.Join(t.TempDir(), "main.js")
		if err := os.WriteFile(bundle, []byte("exports.alpha = function (a) {};\nexports.beta = function (a, b) {};\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		parsed := []webEvent{
			event("Debugger.scriptParsed", map[string]any{"scriptId": "7", "url": "file:///Applications/App.app/Contents/Resources/app.asar/main.js"}),
			event("Debugger.scriptParsed", map[string]any{"scriptId": "8", "url": "webpack://bundle.js"}),
			event("Debugger.scriptParsed", map[string]any{"scriptId": "9", "url": "blob:http://127.0.0.1:9222/9f3a"}),
		}
		// The running module exports alpha plus an omega the disk build lacks, and
		// has dropped beta: that is the join this item exists for.
		fakeDriver(t, webOut{Events: parsed, Steps: []webStepResult{
			okStep("Debugger.enable", map[string]any{}),
			okStep("Runtime.enable", map[string]any{}),
			okStep("Runtime.evaluate", map[string]any{"result": map[string]any{"value": []any{"alpha", "omega"}}}),
		}})
		f := fields(t, run(t, "reconcile_javascript_runtime", "127.0.0.1:9222="+bundle))
		if f["status"] != "matched" || f["static"] != "main.js" || f["scripts_parsed"] != float64(3) || f["exports_evaluated"] != true {
			t.Fatalf("report %v", f)
		}
		if got := numList(t, f["matched"]); !reflect.DeepEqual(got, []string{"alpha"}) {
			t.Errorf("matched %v", got)
		}
		if got := numList(t, f["runtime_exports_only"]); !reflect.DeepEqual(got, []string{"omega"}) {
			t.Errorf("runtime_exports_only %v", got)
		}
		var disk []string
		for _, raw := range f["disk_only_not_parsed"].([]any) {
			disk = append(disk, raw.(map[string]any)["name"].(string))
		}
		if !reflect.DeepEqual(disk, []string{"beta"}) {
			t.Errorf("disk_only_not_parsed %v", disk)
		}
		// main.js is the script the static file was compared against, so only the
		// two scripts that exist at no path on disk are runtime-only.
		var urls []string
		for _, raw := range f["runtime_only"].([]any) {
			urls = append(urls, raw.(map[string]any)["url"].(string))
		}
		if want := []string{"webpack://bundle.js", "blob:http://127.0.0.1:9222/9f3a"}; !reflect.DeepEqual(urls, want) {
			t.Errorf("runtime_only %v, want %v", urls, want)
		}

		// No exports object in the context: fall back to "the script was parsed",
		// which can only ever prove the names exist on disk too.
		fakeDriver(t, webOut{Events: parsed, Steps: []webStepResult{
			okStep("Debugger.enable", map[string]any{}),
			okStep("Runtime.enable", map[string]any{}),
			okStep("Runtime.evaluate", map[string]any{"result": map[string]any{"value": nil}}),
		}})
		f = fields(t, run(t, "reconcile_javascript_runtime", "127.0.0.1:9222="+bundle))
		if f["exports_evaluated"] != false {
			t.Errorf("exports_evaluated %v, want false", f["exports_evaluated"])
		}
		if got := numList(t, f["matched"]); !reflect.DeepEqual(got, []string{"alpha", "beta"}) {
			t.Errorf("fallback matched %v", got)
		}
	})

	t.Run("list_electron_targets", func(t *testing.T) {
		fakeDriver(t, webOut{Targets: targets, Steps: []webStepResult{
			okStep("Runtime.enable", map[string]any{}),
			okStep("Runtime.evaluate", map[string]any{"result": map[string]any{"value": "Mozilla/5.0 Chrome/130.0.0.0 Electron/33.2.1 Safari/537.36"}}),
		}, Events: []webEvent{
			event("Runtime.executionContextCreated", map[string]any{"context": map[string]any{"id": float64(1), "name": "Electron Isolated Context", "origin": "file://", "auxData": map[string]any{"type": "isolated", "isDefault": false}}}),
			event("Runtime.executionContextCreated", map[string]any{"context": map[string]any{"id": float64(2), "name": "", "origin": "file://", "auxData": map[string]any{"type": "default", "isDefault": true}}}),
		}})
		f := fields(t, run(t, "list_electron_targets", "127.0.0.1:9222"))
		if f["verdict"] != "electron" || f["electron_isolated_world"] != true || f["ua_electron_version"] != "33.2.1" {
			t.Errorf("report %v", f)
		}
		if n := len(f["contexts"].([]any)); n != 2 {
			t.Errorf("contexts %d, want 2", n)
		}
	})
}

// TestWebEndpointAbsentIsAnError: with the transport in-process there is no
// interpreter to miss, so a refused endpoint is an error naming the address and
// the cause, not a "node not installed" skip.
func TestWebEndpointAbsentIsAnError(t *testing.T) {
	prev := webTransport
	webTransport = cdpRun
	t.Cleanup(func() { webTransport = prev })
	v, err := runOp("list_browser_targets", "127.0.0.1:1")
	if err == nil {
		t.Fatalf("got %T, want an error for a refused endpoint", v)
	}
	if !strings.Contains(err.Error(), "cdp 127.0.0.1:1") || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error %q must name the endpoint and the connection refusal", err)
	}
}

func TestWebTargetsAreDeclined(t *testing.T) {
	fakeDriver(t, webOut{})
	cases := []struct{ target, want string }{
		{"https://example.com/app", websiteDecline},
		{"ws://127.0.0.1:9222", websiteDecline},
		{"1234", runtimeDecline},
		{"Google Chrome", runtimeDecline},
	}
	for _, c := range cases {
		_, err := runOp("inspect_web_page", c.target)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: err %v, want decline %q", c.target, err, c.want)
		}
	}
}

// B9: an asar is a container, not a script. The analyze ops read a bounded
// window of it, and say so with truncated:true, instead of lexing the whole
// archive as if it were source.
func TestAsarAnalysisIsBounded(t *testing.T) {
	// -race makes the lexer ~6x slower; the assertion is the byte window, not speed.
	t.Setenv("LRECON_OP_DEADLINE", "60s")
	dir := t.TempDir()
	line := []byte("const v = require('./m');\n")
	big := bytes.Repeat(line, maxAsarWebText/len(line)+64)
	archive := writeAsarArchive(t, dir, "app.asar", map[string][]byte{"main.js": big})

	f := fields(t, run(t, "analyze_javascript_application", archive))
	if f["bytes"] != float64(maxAsarWebText) {
		t.Errorf("bytes %v, want the %d-byte asar window", f["bytes"], maxAsarWebText)
	}
	if f["truncated"] != true {
		t.Errorf("truncated %v, want true: the container was cut at the window", f["truncated"])
	}

	w := fields(t, run(t, "analyze_web_bundle", archive))
	if w["bytes"] != float64(maxAsarWebText) || w["truncated"] != true {
		t.Errorf("bundle bytes/truncated = %v/%v, want %d/true", w["bytes"], w["truncated"], maxAsarWebText)
	}
}

// B9: each of the three ops owns a deadline. When it is spent the refusal is a
// JSON envelope that names the timeout and the target shape, not a prose line
// or a process the caller has to kill.
func TestAsarDeadlineEnvelope(t *testing.T) {
	dir := t.TempDir()
	archive := writeAsarArchive(t, dir, "app.asar", map[string][]byte{
		"main.js": []byte("module.exports = 1;\n"),
	})
	outDir := filepath.Join(dir, "out")
	t.Setenv(opDeadlineEnv, "0s")

	for _, op := range []string{"analyze_javascript_application", "analyze_web_bundle", "extract_artifact"} {
		args := []string{"--op", op, "--json"}
		if op == "extract_artifact" {
			args = append(args, "-o", outDir)
		}
		args = append(args, archive)
		stdout, stderr, code := runCLIAll(t, args...)
		if code != 2 {
			t.Fatalf("%s: exit %d, want 2 (stderr %q, stdout %q)", op, code, stderr, stdout)
		}
		var env map[string]any
		if err := json.Unmarshal([]byte(stdout), &env); err != nil {
			t.Fatalf("%s: stdout is not one JSON envelope: %v\n%s", op, err, stdout)
		}
		for key, want := range map[string]string{
			"op": op, "error": "timeout", "kind": "timeout", "stage": "asar",
		} {
			if env[key] != want {
				t.Errorf("%s: envelope %s = %v, want %q (%v)", op, key, env[key], want, env)
			}
		}
	}
	if _, err := os.Stat(outDir); !os.IsNotExist(err) {
		t.Errorf("a timed-out extract_artifact left %s behind", outDir)
	}
}

// The line index must agree with the old count-from-the-start definition at
// every offset, including the newline itself and past the end of the source.
func TestLineIndexMatchesNewlineCount(t *testing.T) {
	for _, src := range []string{"", "no newline", "a\nbb\n\nccc", "\n\n"} {
		ix := newLineIndex(src)
		for off := 0; off <= len(src)+3; off++ {
			n := min(off, len(src))
			want := strings.Count(src[:n], "\n") + 1
			if got := ix.at(off); got != want {
				t.Errorf("%q off %d: line %d, want %d", src, off, got, want)
			}
		}
	}
}

// The destination comes from the target (host:port=<path>), so anything that
// can name an endpoint can name a fixture. capture_adb_screen grew this guard
// after a screenshot erased a Mach-O; the web twin had none, and on 2026-11-03
// it silently replaced a four-byte "MZ..." file with a PNG. The refusal here is
// checked without a driver on purpose: it must happen before the first connect.
func TestCaptureWebScreenshotRejectsNonPNG(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fixture")
	const body = "MZ\x90\x00 a binary, not a screenshot"
	if err := os.WriteFile(bin, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := opCaptureWebScreenshot("127.0.0.1:1=" + bin)
	if err == nil {
		t.Fatal("a non-PNG destination must be refused, not overwritten")
	}
	if !strings.Contains(err.Error(), "not a PNG") || !strings.Contains(err.Error(), "capture_web_screenshot") {
		t.Fatalf("refusal must name the cause and the op, got %q", err)
	}
	if b, _ := os.ReadFile(bin); string(b) != body {
		t.Fatalf("refused destination changed anyway: %q", b)
	}
}
