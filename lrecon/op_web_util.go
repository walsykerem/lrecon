package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Shared plumbing for the 25 WEB items: the file side (text reads, the JS lexer
// every bundle item sits on) and the live side (one CDP driver, exec'd, never a
// browser launched here).

const (
	maxWebText  = 32 << 20 // one bundle or map; bigger is truncated, and says so
	webTimeout  = 60 * time.Second
	webDefaultE = "127.0.0.1:9222"
)

// readWebText reads one source artifact as text. A truncated body is flagged,
// not silently cut: half a bundle reads as a different application.
func readWebText(p string) (string, bool, error) {
	st, err := os.Stat(p)
	if err != nil {
		return "", false, err
	}
	if st.IsDir() {
		return "", false, fmt.Errorf("%s is a directory: pass one file", p)
	}
	f, err := os.Open(p)
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxWebText+1))
	if err != nil {
		return "", false, err
	}
	if len(b) > maxWebText {
		b = b[:maxWebText]
		return string(b), true, nil
	}
	return string(b), false, nil
}

// --- JavaScript lexer (item 180) ---

// jsLexStats is what the lexer itself can state: how much of the file was
// token, and which literals it carried. Imports/exports are read off the code
// regions afterwards, because they are patterns over tokens, not tokens.
type jsLexStats struct {
	Tokens    int
	Comments  int
	Regexes   int
	Templates int
	Strings   []string
}

var jsKeywordsBeforeRegex = map[string]bool{
	"return": true, "typeof": true, "case": true, "in": true, "of": true,
	"new": true, "delete": true, "void": true, "throw": true, "else": true,
	"instanceof": true, "do": true, "yield": true, "await": true,
}

// lexJS walks the source once as a hand-written state machine and returns a copy
// where every string, template, comment and regex body is blanked to spaces
// (newlines kept, so offsets and line numbers stay exact) plus the literal table.
// The blank copy is what the pattern items match against: `require('./x')` inside
// a comment or a quoted example must not become an edge.
func lexJS(src []byte) ([]byte, jsLexStats) {
	out := make([]byte, len(src))
	copy(out, src)
	var st jsLexStats
	var lastWord string // last identifier, for keyword lookbehind
	regexOK := true

	blank := func(from, to int) {
		for i := from; i < to && i < len(out); i++ {
			if src[i] != '\n' {
				out[i] = ' '
			}
		}
	}

	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			j := i + 2
			for j < len(src) && src[j] != '\n' {
				j++
			}
			blank(i, j)
			st.Comments++
			i = j
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			j := i + 2
			for j+1 < len(src) && !(src[j] == '*' && src[j+1] == '/') {
				j++
			}
			if j+1 < len(src) {
				j += 2
			}
			blank(i, j)
			st.Comments++
			i = j
		case c == '\'' || c == '"':
			j := i + 1
			var b strings.Builder
			for j < len(src) && src[j] != c {
				if src[j] == '\\' && j+1 < len(src) {
					b.WriteByte(src[j+1])
					j += 2
					continue
				}
				if src[j] == '\n' {
					break // unterminated: keep the line number, stop at the break
				}
				b.WriteByte(src[j])
				j++
			}
			if j < len(src) && src[j] == c {
				j++
			}
			st.Strings = append(st.Strings, b.String())
			st.Tokens++
			blank(i+1, j-1)
			lastWord, regexOK = "", false
			i = j
		case c == '`':
			j, lit := scanTemplate(src, i)
			st.Strings = append(st.Strings, lit)
			st.Templates++
			st.Tokens++
			blank(i+1, j-1)
			lastWord, regexOK = "", false
			i = j
		case c == '/' && (regexOK || jsKeywordsBeforeRegex[lastWord]):
			j := i + 1
			inClass := false
			for j < len(src) && src[j] != '\n' {
				if src[j] == '\\' {
					j += 2
					continue
				}
				if src[j] == '[' {
					inClass = true
				} else if src[j] == ']' {
					inClass = false
				} else if src[j] == '/' && !inClass {
					break
				}
				j++
			}
			if j < len(src) && src[j] == '/' {
				j++
				for j < len(src) && isJSIdent(src[j]) {
					j++
				}
				st.Regexes++
				st.Tokens++
				blank(i+1, j-1)
				lastWord, regexOK = "", false
				i = j
				continue
			}
			// not a regex after all: it is a division sign
			lastWord = ""
			regexOK = true
			i++
		case isJSIdent(c) && !(c >= '0' && c <= '9'):
			j := i
			for j < len(src) && isJSIdent(src[j]) {
				j++
			}
			lastWord = string(src[i:j])
			st.Tokens++
			regexOK = false
			i = j
		case c >= '0' && c <= '9':
			j := i
			for j < len(src) && (isJSIdent(src[j]) || src[j] == '.') {
				j++
			}
			st.Tokens++
			lastWord, regexOK = "", false
			i = j
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		default:
			st.Tokens++
			lastWord = ""
			regexOK = strings.IndexByte("(,=:[!&|?{};+-*%<>~^", c) >= 0
			i++
		}
	}
	return out, st
}

func isJSIdent(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// scanTemplate ends a template literal at its closing backtick, stepping over
// ${...} bodies (nested braces, strings, regexes) so an inner backtick-in-
// expression does not end the literal early.
func scanTemplate(src []byte, start int) (int, string) {
	var lit strings.Builder
	i := start + 1
	for i < len(src) {
		switch c := src[i]; c {
		case '`':
			return i + 1, lit.String()
		case '\\':
			if i+1 < len(src) {
				lit.WriteByte(src[i+1])
			}
			i += 2
		case '$':
			if i+1 < len(src) && src[i+1] == '{' {
				i = skipTemplateExpr(src, i+2)
				continue
			}
			lit.WriteByte(c)
			i++
		default:
			lit.WriteByte(c)
			i++
		}
	}
	return i, lit.String()
}

func skipTemplateExpr(src []byte, i int) int {
	depth := 1
	for i < len(src) {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i + 1
			}
		case '\'', '"':
			q := src[i]
			i++
			for i < len(src) && src[i] != q {
				if src[i] == '\\' {
					i++
				}
				i++
			}
		case '`':
			n, _ := scanTemplate(src, i)
			i = n
			continue
		case '/':
			if i+1 < len(src) && src[i+1] == '/' {
				for i < len(src) && src[i] != '\n' {
					i++
				}
				continue
			}
			if i+1 < len(src) && src[i+1] == '*' {
				i += 2
				for i+1 < len(src) && !(src[i] == '*' && src[i+1] == '/') {
					i++
				}
				i += 2
				continue
			}
		}
		i++
	}
	return i
}

// --- import/require/export edges (items 181, 203) ---

type jsEdge struct {
	Kind string `json:"kind"` // import | export-from | require | dynamic-import
	Spec string `json:"spec"`
	Line int    `json:"line"`
}

var (
	jsImportRe   = regexp.MustCompile(`\bimport\s+(?:[^'"\n;]*?\s+from\s+)?['"]([^'"\n]+)['"]`)
	jsExportFrom = regexp.MustCompile(`\bexport\s+[^'"\n;]*?\s+from\s+['"]([^'"\n]+)['"]`)
	jsRequireRe  = regexp.MustCompile(`\brequire\s*\(\s*['"]([^'"\n]+)['"]\s*\)`)
	jsDynamicImp = regexp.MustCompile(`\bimport\s*\(\s*['"]([^'"\n]+)['"]\s*\)`)
)

// jsEdges reads module edges off the code regions only: masked keeps comments
// and string bodies blank, so a pattern that starts inside one is skipped.
func jsEdges(src string, masked []byte) []jsEdge {
	return jsEdgesIndexed(src, masked, newLineIndex(src))
}

// jsEdgesIndexed is jsEdges with a prebuilt line index. A big container has
// thousands of matches; counting newlines from the start for each one made the
// scan quadratic (measured: a 20 MB asar took 13 s).
func jsEdgesIndexed(src string, masked []byte, lines lineIndex) []jsEdge {
	var out []jsEdge
	add := func(re *regexp.Regexp, kind string) {
		for _, m := range re.FindAllStringSubmatchIndex(src, -1) {
			if m[0] >= len(masked) || masked[m[0]] == ' ' {
				continue // the keyword itself sits in a string or a comment
			}
			out = append(out, jsEdge{Kind: kind, Spec: src[m[2]:m[3]], Line: lines.at(m[0])})
		}
	}
	add(jsExportFrom, "export-from")
	add(jsImportRe, "import")
	add(jsDynamicImp, "dynamic-import")
	add(jsRequireRe, "require")
	// Grouping by kind is an artefact of the four scans; a reader wants the
	// bundle's own order.
	sort.SliceStable(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out
}

// dedupeEdges keeps the first sighting of one (kind, spec) pair, in source order.
func dedupeEdges(in []jsEdge) []jsEdge {
	seen := map[string]bool{}
	out := make([]jsEdge, 0, len(in))
	for _, e := range in {
		k := e.Kind + "\x00" + e.Spec
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, e)
	}
	return out
}

// lineIndex holds the byte offset of every newline, so a line number costs a
// binary search instead of a scan from the start of the file. lineAt did the
// scan, which turned a file with many matches into quadratic work.
type lineIndex []int

func newLineIndex(src string) lineIndex {
	idx := make(lineIndex, 0, strings.Count(src, "\n"))
	for i := 0; i < len(src); i++ {
		if src[i] == '\n' {
			idx = append(idx, i)
		}
	}
	return idx
}

// at returns the 1-based line of off, counting newlines before it.
func (ix lineIndex) at(off int) int {
	return sort.SearchInts(ix, off) + 1
}

// --- live side: one DevTools endpoint, one exec'd driver ---

// webTarget splits `host:port[=arg]`. Only loopback endpoints are read: the
// items attach to a debug port on this machine, never to a remote host.
func webTarget(target string) (ep, arg string, err error) {
	if target == "" {
		return webDefaultE, "", nil
	}
	if looksLikeWebsite(target) {
		return "", "", errors.New(websiteDecline)
	}
	if looksLikePID(target) || (!strings.Contains(target, ":") && looksLikeProcessName(target)) {
		return "", "", errors.New(runtimeDecline)
	}
	ep, arg, _ = strings.Cut(target, "=")
	if !strings.Contains(ep, ":") {
		// A bare port is shorthand ("9222"); anything else is a file path or a
		// word, and turning it into 127.0.0.1:<word> made node print its own
		// eval error instead of a bad_arg refusal.
		if !digitsOnly(ep) {
			return "", "", fmt.Errorf("%s is not a DevTools endpoint: pass host:port from --remote-debugging-port (e.g. 127.0.0.1:9222), optionally =arg", target)
		}
		ep = webDefaultE[:strings.LastIndexByte(webDefaultE, ':')+1] + ep // bare port
	}
	host, port, err := net.SplitHostPort(ep)
	if err != nil || !digitsOnly(port) {
		return "", "", fmt.Errorf("%s is not a DevTools endpoint: pass host:port from --remote-debugging-port (e.g. 127.0.0.1:9222), optionally =arg", target)
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return "", "", fmt.Errorf("refusing %s: lrecon reads a debug port on this machine only, never a remote host", ep)
	}
	return net.JoinHostPort(host, port), arg, nil
}

// digitsOnly reports a non-empty run of ASCII digits: the only shape a port
// may take here. net.SplitHostPort accepts any text after the colon, so a path
// like /tmp/app.asar passed "port" validation and became a host:path endpoint.
func digitsOnly(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

type webStep struct {
	Method string         `json:"method"`
	Params map[string]any `json:"params,omitempty"`
}

type webCollect struct {
	Ms       int      `json:"ms"`
	Prefixes []string `json:"prefixes"`
}

// webSpec is the whole instruction to the driver: what to attach to, which CDP
// calls in which order, and which events to collect while it does.
type webSpec struct {
	Endpoint string         `json:"endpoint"`
	Mode     string         `json:"mode"` // list | session
	Pick     map[string]any `json:"pick,omitempty"`
	Steps    []webStep      `json:"steps,omitempty"`
	Collect  *webCollect    `json:"collect,omitempty"`
	Resume   bool           `json:"resume,omitempty"` // resume after a Debugger.paused
	Op       string         `json:"-"`
}

type webTargetRow struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Title    string `json:"title"`
	URL      string `json:"url"`
	Attached bool   `json:"attached"`
	WS       string `json:"webSocketDebuggerUrl"`
}

type webStepError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type webStepResult struct {
	Method string         `json:"method"`
	Ok     bool           `json:"ok"`
	Result map[string]any `json:"result"`
	Error  *webStepError  `json:"error"`
}

type webEvent struct {
	Method string         `json:"method"`
	Params map[string]any `json:"params"`
}

type webOut struct {
	Targets []webTargetRow  `json:"targets"`
	Version map[string]any  `json:"version"`
	Target  *webTargetRow   `json:"target"`
	Steps   []webStepResult `json:"steps"`
	Events  []webEvent      `json:"events"`
	Resumed bool            `json:"resumed"`
}

// webRun executes one driver spec against ep. The transport is in-process
// (cdp.go), so the old "node not installed" skip is gone: nothing external
// stands between the op and the endpoint's JSON.
func webRun(opName, ep string, spec webSpec) (webOut, *skip, error) {
	spec.Endpoint, spec.Op = ep, opName
	ctx, cancel := context.WithTimeout(context.Background(), webTimeout)
	defer cancel()
	out, err := webTransport(ctx, spec)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return out, nil, fmt.Errorf("cdp %s: driver timed out after %s", ep, webTimeout)
		}
		return out, nil, fmt.Errorf("cdp %s: %w", ep, err)
	}
	return out, nil, nil
}

// step returns one call's result, turning a CDP error into a Go error that names
// the method: a silently dropped step would make the item claim more than it saw.
func (o webOut) step(i int) (map[string]any, error) {
	if i >= len(o.Steps) {
		return nil, fmt.Errorf("driver returned %d steps, want at least %d", len(o.Steps), i+1)
	}
	s := o.Steps[i]
	if !s.Ok {
		code := 0
		msg := "no error body"
		if s.Error != nil {
			code, msg = s.Error.Code, s.Error.Message
		}
		return nil, fmt.Errorf("cdp %s failed (%d): %s", s.Method, code, msg)
	}
	return s.Result, nil
}

func num(v any) float64 {
	f, _ := v.(float64)
	return f
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// nested walks an untyped CDP result: nested(r, "result", "objectId").
func nested(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

// scriptRow is one Debugger.scriptParsed event, the shape y73/y74 read.
type scriptRow struct {
	ScriptID     string `json:"scriptId"`
	URL          string `json:"url"`
	SourceMapURL string `json:"sourceMapURL"`
	HasSourceURL bool   `json:"hasSourceURL"`
}

func scriptsFrom(events []webEvent) []scriptRow {
	var out []scriptRow
	for _, e := range events {
		if e.Method != "Debugger.scriptParsed" {
			continue
		}
		out = append(out, scriptRow{
			ScriptID:     str(e.Params["scriptId"]),
			URL:          str(e.Params["url"]),
			SourceMapURL: str(e.Params["sourceMapURL"]),
			HasSourceURL: e.Params["hasSourceURL"] == true,
		})
	}
	return out
}

// asarMemberPath cuts a file:// script URL back to its asar-relative member, the
// form the static side speaks (lrecon/asar.go:505 walks the same rels). An empty
// string means the URL is runtime-only (eval, blob, data, http).
func asarMemberPath(u string) string {
	p := strings.TrimPrefix(u, "file://")
	if p == u || p == "" {
		return ""
	}
	for _, marker := range []string{"/app.asar/", "/app.asar.unpacked/"} {
		if _, after, ok := strings.Cut(p, marker); ok {
			return path.Clean(after)
		}
	}
	return ""
}

// --- static side: source map v3 ---

// webSourceMap is the fields this package reads out of a v3 map. Mappings is
// kept as text: decoding is per segment, below.
type webSourceMap struct {
	Version        int       `json:"version"`
	File           string    `json:"file"`
	SourceRoot     string    `json:"sourceRoot"`
	Sources        []string  `json:"sources"`
	SourcesContent []*string `json:"sourcesContent"`
	Names          []string  `json:"names"`
	Mappings       string    `json:"mappings"`
}

// mapSegment is one decoded mapping: a generated position and, when the segment
// carries four or five fields, the original file/line/column it came from.
type mapSegment struct {
	GenLine  int
	GenCol   int
	Source   int
	OrigLine int
	OrigCol  int
	Name     int
}

// loadSourceMap reads the map a script points at. The URL comes from the same
// trailer regex asar.go already scans for, so an inline data: map is decoded
// here rather than fetched.
func loadSourceMap(script string, body []byte) (*webSourceMap, string, error) {
	for _, re := range []*regexp.Regexp{sourceMapRe, sourceMapBlockRe} {
		m := re.FindSubmatch(body)
		if m == nil {
			continue
		}
		url := strings.TrimSpace(string(m[1]))
		var raw []byte
		where := url
		switch {
		case strings.HasPrefix(url, "data:"):
			_, after, ok := strings.Cut(url, "base64,")
			if !ok {
				return nil, "", fmt.Errorf("%s: inline source map is not base64", script)
			}
			dec, err := base64.StdEncoding.DecodeString(after)
			if err != nil {
				return nil, "", fmt.Errorf("%s: inline source map: %v", script, err)
			}
			raw = dec
		default:
			if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "//") {
				return nil, "", fmt.Errorf("%s points at a remote source map %s: download it and pass it here (lrecon never fetches)", script, url)
			}
			where = filepath.Join(filepath.Dir(script), filepath.FromSlash(strings.SplitN(url, "?", 2)[0]))
			b, err := opRead(where, opMaxFile)
			if err != nil {
				return nil, "", fmt.Errorf("%s: source map: %v", script, err)
			}
			raw = b
		}
		var sm webSourceMap
		if err := json.Unmarshal(raw, &sm); err != nil {
			return nil, "", fmt.Errorf("%s: %s is not a JSON source map: %v", script, where, err)
		}
		if sm.Version != 3 {
			return nil, "", fmt.Errorf("%s is not a v3 source map (version %d); only v3 maps carry mappings", where, sm.Version)
		}
		return &sm, where, nil
	}
	return nil, "", fmt.Errorf("%s has no sourceMappingURL trailer: nothing to recover", script)
}

const b64Order = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

var b64Index = func() [256]int8 {
	var t [256]int8
	for i := range t {
		t[i] = -1
	}
	for i := range len(b64Order) {
		t[b64Order[i]] = int8(i)
	}
	return t
}()

// decodeVLQ reads one base64 VLQ value starting at i and returns it with the
// index after it. 32 is the continuation bit, the low bit is the sign.
func decodeVLQ(s string, i int) (int, int, error) {
	shift, acc := 0, 0
	for {
		if i >= len(s) {
			return 0, i, fmt.Errorf("truncated VLQ at end of mappings")
		}
		d := b64Index[s[i]]
		if d < 0 {
			return 0, i, fmt.Errorf("byte %q at %d is not base64", s[i], i)
		}
		i++
		acc += int(d&31) << shift
		if d&32 == 0 {
			if acc&1 == 1 {
				return -(acc >> 1), i, nil
			}
			return acc >> 1, i, nil
		}
		shift += 5
		if shift > 30 {
			return 0, i, fmt.Errorf("VLQ wider than 30 bits at %d", i)
		}
	}
}

// decodeMappings walks the mappings string. Line separators are ';' and segment
// separators ',', and every field is relative to the previous segment, which is
// the part that makes the table look wrong when it is skipped. limit > 0 stops
// the walk after that many segments so a huge table cannot allocate without
// bound; the caller reports the cut.
func decodeMappings(mappings string, limit int) ([]mapSegment, error) {
	var out []mapSegment
	src, oline, ocol, name := 0, 0, 0, 0
	line, col := 0, 0
	for i := 0; i < len(mappings); {
		if limit > 0 && len(out) >= limit {
			return out, nil
		}
		switch mappings[i] {
		case ';':
			line++
			col = 0
			i++
			continue
		case ',':
			i++
			continue
		}
		seg := mapSegment{GenLine: line, GenCol: col, Source: -1, OrigLine: -1, OrigCol: -1, Name: -1}
		v, j, err := decodeVLQ(mappings, i)
		if err != nil {
			return nil, err
		}
		col += v
		seg.GenCol = col
		i = j
		if i < len(mappings) && mappings[i] != ',' && mappings[i] != ';' {
			if v, j, err = decodeVLQ(mappings, i); err != nil {
				return nil, err
			}
			src += v
			i = j
			if v, j, err = decodeVLQ(mappings, i); err != nil {
				return nil, err
			}
			oline += v
			i = j
			if v, j, err = decodeVLQ(mappings, i); err != nil {
				return nil, err
			}
			ocol += v
			seg.Source, seg.OrigLine, seg.OrigCol = src, oline, ocol
			i = j
			if i < len(mappings) && mappings[i] != ',' && mappings[i] != ';' {
				if v, j, err = decodeVLQ(mappings, i); err != nil {
					return nil, err
				}
				name += v
				seg.Name = name
				i = j
			}
		}
		out = append(out, seg)
	}
	return out, nil
}

// --- static side: one network capture, joined by requestId ---

// webRequestRow is one request as the Network domain reports it: the URL and
// method from requestWillBeSent, the status and mime joined in later by id.
// There is no sha256 here: getResponseBody is not called, so bodies is false and
// says so instead of pretending the status stands in for the body.
type webRequestRow struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Status int    `json:"status"`
	Mime   string `json:"mime_type,omitempty"`
}

func captureRequests(events []webEvent) []webRequestRow {
	rows := map[string]*webRequestRow{}
	var order []string
	for _, e := range events {
		id := str(e.Params["requestId"])
		switch e.Method {
		case "Network.requestWillBeSent":
			req, _ := e.Params["request"].(map[string]any)
			if id == "" || req == nil {
				continue
			}
			if _, ok := rows[id]; !ok {
				order = append(order, id)
			}
			rows[id] = &webRequestRow{Method: str(req["method"]), URL: str(req["url"])}
		case "Network.responseReceived":
			resp, _ := e.Params["response"].(map[string]any)
			if resp == nil || rows[id] == nil {
				continue
			}
			rows[id].Status = int(num(resp["status"]))
			rows[id].Mime = str(resp["mimeType"])
		}
	}
	out := make([]webRequestRow, 0, len(order))
	for _, id := range order {
		out = append(out, *rows[id])
	}
	return out
}

func readJSONFile(p string, v any) error {
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s is not JSON: %v", p, err)
	}
	return nil
}

func writeJSONFile(p string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, append(b, '\n'), 0o644)
}
