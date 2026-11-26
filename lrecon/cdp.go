package main

// The CDP transport used to be a JavaScript driver run through node. node is a
// 90 MB runtime the tool does not otherwise need, and the driver's whole job was
// three things the standard library already speaks: two HTTP GETs against
// /json/list and /json/version, one WebSocket session, and JSON-RPC framing.
// This file is that driver in Go, so a DevTools port is read without any
// interpreter on the host. What stays out of scope is deliberate: no TLS trust
// store beyond the system one, no permessage-deflate, no reconnect — DevTools
// endpoints are loopback, plain ws://, one session per answer.

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	cdpMaxFrame = 32 << 20
	cdpCollect  = 1000 * time.Millisecond // the driver's default collect window
)

// cdpMaxBody bounds one discovery body (/json/list, /json/version). A var so a
// test can lower it instead of serving 32 MiB.
var cdpMaxBody int64 = 32 << 20

// webTransport is the one seam between the ops and the wire. Production always
// uses cdpRun; tests replace it to exercise the op layer without a browser.
var webTransport = cdpRun

// cdpMaxMessage bounds one reassembled message. A frame is already capped, but
// continuation frames were not: an endpoint (the WS URL comes from the target's
// own /json/list) could keep the driver appending until memory ran out. A var so
// a test can lower it instead of allocating 32 MiB.
var cdpMaxMessage int64 = cdpMaxFrame

// cdpRun is the whole driver: list targets, optionally attach, run the steps,
// collect the events. Every decision about what to ask lives in the op.
func cdpRun(ctx context.Context, spec webSpec) (webOut, error) {
	var out webOut
	// The CLI validates at webTarget; re-check at the transport so the URL below can only be loopback.
	ep, _, err := webTarget(spec.Endpoint)
	if err != nil {
		return out, fmt.Errorf("cdp endpoint: %w", err)
	}
	base := "http://" + ep // NOSONAR S5332: DevTools is loopback-only plain HTTP/ws by design; webTarget refused remote hosts above.
	body, err := cdpGet(ctx, base+"/json/list")
	if err != nil {
		return out, fmt.Errorf("/json/list: %w", err)
	}
	if err := json.Unmarshal(body, &out.Targets); err != nil {
		return out, fmt.Errorf("/json/list returned no target array: %w", err)
	}
	if body, err := cdpGet(ctx, base+"/json/version"); err != nil {
		// The version is context, not a precondition: an endpoint that answers
		// the target list but not the version still gets its answer.
		out.Version = map[string]any{"error": err.Error()}
	} else if err := json.Unmarshal(body, &out.Version); err != nil {
		out.Version = map[string]any{"error": err.Error()}
	}
	if spec.Mode != "session" {
		return out, nil
	}
	t, err := cdpPickTarget(out.Targets, spec.Pick)
	if err != nil {
		return out, err
	}
	out.Target = &webTargetRow{ID: t.ID, Type: t.Type, Title: t.Title, URL: t.URL, WS: t.WS}
	ws, err := cdpDial(ctx, t.WS)
	if err != nil {
		return out, err
	}
	defer ws.close()
	for _, st := range spec.Steps {
		params := map[string]any{}
		for k, v := range st.Params {
			dv := cdpDeref(out, v)
			if dv == nil {
				continue // an unresolved $ref is absent, never a null argument
			}
			params[k] = dv
		}
		res, stepErr, err := ws.call(ctx, st.Method, params)
		if err != nil {
			return out, err
		}
		if stepErr != nil {
			out.Steps = append(out.Steps, webStepResult{Method: st.Method, Error: stepErr})
			continue
		}
		out.Steps = append(out.Steps, webStepResult{Method: st.Method, Ok: true, Result: res})
	}
	if spec.Collect != nil {
		wait := cdpCollect
		if spec.Collect.Ms > 0 {
			wait = time.Duration(spec.Collect.Ms) * time.Millisecond
		}
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		case <-time.After(wait):
		}
		pf := spec.Collect.Prefixes
		var kept []webEvent
		for _, e := range ws.takeEvents() {
			for _, p := range pf {
				if strings.HasPrefix(e.Method, p) {
					kept = append(kept, e)
					break
				}
			}
		}
		out.Events = kept
	} else {
		out.Events = ws.takeEvents()
	}
	if spec.Resume && hasEvent(out.Events, "Debugger.paused") {
		if _, _, err := ws.call(ctx, "Debugger.resume", map[string]any{}); err != nil {
			return out, err
		}
		out.Resumed = true
	}
	return out, nil
}

func hasEvent(events []webEvent, method string) bool {
	for _, e := range events {
		if e.Method == method {
			return true
		}
	}
	return false
}

// cdpPickTarget follows the driver's order: an explicit id, then the first
// target of the requested type (page by default), then whatever came first.
func cdpPickTarget(targets []webTargetRow, pick map[string]any) (webTargetRow, error) {
	id, _ := pick["id"].(string)
	typ, _ := pick["type"].(string)
	if typ == "" {
		typ = "page"
	}
	for _, t := range targets {
		if id != "" && t.ID == id {
			return cdpAttachable(t)
		}
	}
	for _, t := range targets {
		if t.Type == typ {
			return cdpAttachable(t)
		}
	}
	if len(targets) == 0 {
		return webTargetRow{}, errors.New("no attachable target in /json/list")
	}
	return cdpAttachable(targets[0])
}

func cdpAttachable(t webTargetRow) (webTargetRow, error) {
	if t.WS == "" {
		return t, errors.New("no attachable target in /json/list")
	}
	return t, nil
}

// cdpDeref resolves the driver's $-references against the steps already run.
func cdpDeref(out webOut, v any) any {
	s, ok := v.(string)
	if !ok || !strings.HasPrefix(s, "$") {
		return v
	}
	targetURL := ""
	if out.Target != nil {
		targetURL = out.Target.URL
	}
	switch s {
	case "$target.url":
		return targetURL
	case "$target.urlQuote":
		return cdpQuoteMeta(targetURL)
	}
	rest := strings.TrimPrefix(s, "$")
	num, pathPart, _ := strings.Cut(rest, ".")
	n, err := strconv.Atoi(num)
	if err != nil || n < 0 || n >= len(out.Steps) {
		return nil // an unresolved $ref is absent, never a literal argument
	}
	var cur any = out.Steps[n].Result
	if pathPart == "" {
		return cur
	}
	for k := range strings.SplitSeq(pathPart, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[k]
	}
	return cur
}

// cdpQuoteMeta is the JS /[.*+?^${}()|[\]\\]/g replacement the driver applied to
// the target URL before using it inside a regular expression.
func cdpQuoteMeta(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '.', '*', '+', '?', '^', '$', '{', '}', '(', ')', '|', '[', ']', '\\':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// cdpGet is one loopback GET. The transport ignores proxy environment: a
// devtools port on this machine is never reached through a corporate proxy.
func cdpGet(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}
	// One byte past the cap tells a body that fits from one that was cut: a
	// silent cut surfaced as "unexpected end of JSON input" instead of naming
	// the limit that was hit.
	body, err := io.ReadAll(io.LimitReader(resp.Body, cdpMaxBody+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > cdpMaxBody {
		return nil, fmt.Errorf("response over %d bytes", cdpMaxBody)
	}
	return body, nil
}

// --- WebSocket client (RFC 6455, the subset a DevTools endpoint needs) ---

type cdpWS struct {
	conn net.Conn
	br   *bufio.Reader

	mu     sync.Mutex // write lock
	seq    int
	pendMu sync.Mutex
	pend   map[int]chan cdpReply
	evMu   sync.Mutex
	events []webEvent
	done   chan struct{}
	failed bool // done was released; guarded by pendMu
	err    error
}

type cdpReply struct {
	result map[string]any
	err    *webStepError
}

func cdpDial(ctx context.Context, raw string) (*cdpWS, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("websocket url %q: %w", raw, err)
	}
	host := u.Host
	port := u.Port()
	switch u.Scheme {
	case "ws":
		if port == "" {
			host += ":80"
		}
	case "wss":
		if port == "" {
			host += ":443"
		}
	default:
		return nil, fmt.Errorf("websocket url %q: only ws:// and wss:// are attachable", raw)
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, webTimeout)
		defer cancel()
	}
	d := &net.Dialer{}
	// A deadline ctx carries must also bound the TLS handshake: DialContext
	// honors ctx, DialWithDialer only honors the dialer's own Deadline.
	if dl, ok := ctx.Deadline(); ok {
		d.Deadline = dl
	}
	var conn net.Conn
	if u.Scheme == "wss" {
		conn, err = tls.DialWithDialer(d, "tcp", host, &tls.Config{ServerName: u.Hostname()})
	} else {
		conn, err = d.DialContext(ctx, "tcp", host)
	}
	if err != nil {
		return nil, fmt.Errorf("websocket open failed: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	keyRaw := make([]byte, 16)
	if _, err := rand.Read(keyRaw); err != nil {
		conn.Close()
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyRaw)
	req := "GET " + u.RequestURI() + " HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("websocket open failed: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("websocket handshake: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, fmt.Errorf("websocket handshake: %s", resp.Status)
	}
	w := &cdpWS{conn: conn, br: br, pend: map[int]chan cdpReply{}, done: make(chan struct{})}
	go w.readLoop()
	return w, nil
}

// fail records the first transport error and releases done exactly once. Two
// callers do race here (readLoop sees the dead socket while cdpRun's deferred
// close reports the session over), and closing done twice panicked the op.
func (w *cdpWS) fail(err error) {
	w.pendMu.Lock()
	if w.err == nil {
		w.err = err
	}
	if !w.failed {
		w.failed = true
		close(w.done)
	}
	w.pendMu.Unlock()
}

func (w *cdpWS) close() {
	w.mu.Lock()
	_ = w.writeFrame(0x8, nil)
	w.mu.Unlock()
	w.fail(errors.New("websocket closed"))
	_ = w.conn.Close()
}

func (w *cdpWS) call(ctx context.Context, method string, params map[string]any) (map[string]any, *webStepError, error) {
	w.pendMu.Lock()
	w.seq++
	id := w.seq
	ch := make(chan cdpReply, 1)
	w.pend[id] = ch
	w.pendMu.Unlock()
	// Every exit below leaves the entry behind otherwise: a step that times out
	// or a write against a dead socket would leak one channel per call.
	defer func() {
		w.pendMu.Lock()
		delete(w.pend, id)
		w.pendMu.Unlock()
	}()

	body, err := json.Marshal(map[string]any{"id": id, "method": method, "params": params})
	if err != nil {
		return nil, nil, err
	}
	w.mu.Lock()
	err = w.writeFrame(0x1, body)
	w.mu.Unlock()
	if err != nil {
		return nil, nil, fmt.Errorf("cdp %s: %w", method, err)
	}
	select {
	case r := <-ch:
		return r.result, r.err, nil
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-w.done:
		w.pendMu.Lock()
		err := w.err
		w.pendMu.Unlock()
		return nil, nil, fmt.Errorf("cdp %s: %w", method, err)
	}
}

func (w *cdpWS) takeEvents() []webEvent {
	w.evMu.Lock()
	defer w.evMu.Unlock()
	out := w.events
	w.events = nil
	return out
}

func (w *cdpWS) addEvent(e webEvent) {
	w.evMu.Lock()
	w.events = append(w.events, e)
	w.evMu.Unlock()
}

func (w *cdpWS) readLoop() {
	var buf []byte
	for {
		op, fin, payload, err := w.readFrame()
		if err != nil {
			w.fail(err)
			return
		}
		switch op {
		case 0x1, 0x2: // text, binary
			if int64(len(payload)) > cdpMaxMessage {
				w.fail(fmt.Errorf("websocket message over %d bytes", cdpMaxMessage))
				return
			}
			buf = append(buf[:0], payload...)
		case 0x0: // continuation
			if int64(len(buf))+int64(len(payload)) > cdpMaxMessage {
				w.fail(fmt.Errorf("websocket message over %d bytes", cdpMaxMessage))
				return
			}
			buf = append(buf, payload...)
		case 0x8: // close
			w.fail(errors.New("websocket closed by the endpoint"))
			return
		case 0x9: // ping
			w.mu.Lock()
			_ = w.writeFrame(0xA, payload)
			w.mu.Unlock()
			continue
		default: // pong and reserved frames carry no message
			continue
		}
		if !fin {
			continue
		}
		w.dispatch(buf)
		buf = buf[:0]
	}
}

func (w *cdpWS) dispatch(raw []byte) {
	var m struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params map[string]any  `json:"params"`
		Result map[string]any  `json:"result"`
		Error  *webStepError   `json:"error"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return
	}
	if id := strings.TrimSpace(string(m.ID)); id != "" && id != "null" {
		n, err := strconv.Atoi(id)
		if err != nil {
			return
		}
		w.pendMu.Lock()
		ch, ok := w.pend[n]
		delete(w.pend, n)
		w.pendMu.Unlock()
		if ok {
			ch <- cdpReply{result: m.Result, err: m.Error}
		}
		return
	}
	if m.Method != "" {
		w.addEvent(webEvent{Method: m.Method, Params: m.Params})
	}
}

func (w *cdpWS) readFrame() (op byte, fin bool, payload []byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(w.br, h[:]); err != nil {
		return 0, false, nil, err
	}
	fin = h[0]&0x80 != 0
	op = h[0] & 0x0f
	masked := h[1]&0x80 != 0
	n := int64(h[1] & 0x7f)
	switch n {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(w.br, ext[:]); err != nil {
			return 0, false, nil, err
		}
		n = int64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(w.br, ext[:]); err != nil {
			return 0, false, nil, err
		}
		n = int64(binary.BigEndian.Uint64(ext[:]))
	}
	if n < 0 || n > cdpMaxFrame {
		return 0, false, nil, fmt.Errorf("websocket frame of %d bytes is out of range", n)
	}
	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(w.br, mask[:]); err != nil {
			return 0, false, nil, err
		}
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(w.br, payload); err != nil {
		return 0, false, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return op, fin, payload, nil
}

// writeFrame writes one masked client frame; the caller holds w.mu.
func (w *cdpWS) writeFrame(op byte, payload []byte) error {
	hdr := make([]byte, 0, 14)
	hdr = append(hdr, 0x80|op)
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, byte(n)|0x80)
	case n <= 0xffff:
		hdr = append(hdr, 126|0x80, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 127|0x80)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		hdr = append(hdr, ext[:]...)
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	hdr = append(hdr, mask[:]...)
	out := make([]byte, 0, len(hdr)+n)
	out = append(out, hdr...)
	start := len(out)
	out = append(out, payload...)
	for i := range n {
		out[start+i] ^= mask[i%4]
	}
	_, err := w.conn.Write(out)
	return err
}
