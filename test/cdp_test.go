package main

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// A transport failure must survive into the call error. call used to clear
// w.err on entry, so a call made after the socket died reported "cdp ...: <nil>".
func TestCdpCallReportsTransportError(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	// Drain the request frame so writeFrame does not block on the synchronous pipe.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := server.Read(buf); err != nil {
				return
			}
		}
	}()
	w := &cdpWS{conn: client, br: bufio.NewReader(client), pend: map[int]chan cdpReply{}, done: make(chan struct{})}
	w.fail(errors.New("transport exploded"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _, err := w.call(ctx, "Runtime.evaluate", nil)
	if err == nil {
		t.Fatal("call on a dead connection returned no error")
	}
	if !strings.Contains(err.Error(), "transport exploded") {
		t.Fatalf("err = %v, want the transport failure, not a masked nil", err)
	}
	if strings.Contains(err.Error(), "<nil>") {
		t.Fatalf("err = %v, the underlying error was masked", err)
	}
}

func writeWSFrame(t *testing.T, c net.Conn, op byte, fin bool, payload []byte) {
	t.Helper()
	if len(payload) > 125 {
		t.Fatalf("test frame too big: %d", len(payload))
	}
	b0 := byte(0x80) | op
	if !fin {
		b0 &^= 0x80
	}
	frame := append([]byte{b0, byte(len(payload))}, payload...)
	if _, err := c.Write(frame); err != nil {
		t.Fatalf("write frame: %v", err)
	}
}

// An out-of-range $N reference is absent, matching the "never a literal $N
// argument" contract; it used to be sent to the browser as the string "$9.x".
func TestCdpDerefUnresolvedIsAbsent(t *testing.T) {
	out := webOut{Steps: []webStepResult{{Result: map[string]any{"ok": true}}}}
	if got := cdpDeref(out, "$9.x"); got != nil {
		t.Fatalf("cdpDeref($9.x) = %#v, want nil", got)
	}
	if got := cdpDeref(out, "$0.ok"); got != true {
		t.Fatalf("cdpDeref($0.ok) = %#v, want true", got)
	}
}

// Continuation frames are bounded too: without a message cap a hostile endpoint
// (the WS URL comes from its own /json/list) could grow the buffer forever.
func TestCdpMessageAccumulationCapped(t *testing.T) {
	old := cdpMaxMessage
	cdpMaxMessage = 8
	t.Cleanup(func() { cdpMaxMessage = old })
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	w := &cdpWS{conn: client, br: bufio.NewReader(client), pend: map[int]chan cdpReply{}, done: make(chan struct{})}
	go w.readLoop()
	writeWSFrame(t, server, 0x1, false, []byte("1234"))
	writeWSFrame(t, server, 0x0, false, []byte("5678"))
	writeWSFrame(t, server, 0x0, true, []byte("9"))
	select {
	case <-w.done:
	case <-time.After(2 * time.Second):
		t.Fatal("readLoop kept accumulating past the cap")
	}
	w.pendMu.Lock()
	err := w.err
	w.pendMu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "websocket message over") {
		t.Fatalf("err = %v, want a message-size refusal", err)
	}
}

// A TLS peer that accepts the socket and then says nothing must not pin the
// driver: the ctx deadline has to reach the handshake, not just DialContext.
func TestCdpDialWssHonorsContextDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("listen: %v", err)
	}
	defer ln.Close()
	release := make(chan struct{})
	defer close(release)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		<-release // hold the socket open without completing a TLS handshake
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := cdpDial(ctx, "wss://"+ln.Addr().String()+"/devtools/browser/x"); err == nil {
		t.Fatal("a silent TLS peer was accepted")
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("cdpDial took %v, the ctx deadline did not reach the TLS handshake", took)
	}
}

// Two failures collide on a live host: readLoop reports the dead socket at the
// same moment cdpRun's deferred close reports the session over. fail used to
// release done outside any lock, so both callers could pass the "closed
// already" check and the second close(w.done) panicked the whole op.
func TestCdpFailIsIdempotentUnderRace(t *testing.T) {
	for round := range 300 {
		w := &cdpWS{pend: map[int]chan cdpReply{}, done: make(chan struct{})}
		var ready, finished sync.WaitGroup
		ready.Add(8)
		finished.Add(8)
		release := make(chan struct{})
		for range 8 {
			go func() {
				defer finished.Done()
				ready.Done()
				<-release
				w.fail(errors.New("boom"))
			}()
		}
		ready.Wait()
		close(release)
		finished.Wait()
		select {
		case <-w.done:
		default:
			t.Fatalf("round %d: done was not closed", round)
		}
		if w.err == nil {
			t.Fatalf("round %d: transport error was dropped", round)
		}
	}
}

// A call that gives up (ctx deadline, write failure) has to drop its pending
// entry, or every timed-out step leaves a channel behind for the rest of the
// session.
func TestCdpCallReleasesPendingOnTimeout(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := server.Read(buf); err != nil {
				return
			}
		}
	}()
	w := &cdpWS{conn: client, br: bufio.NewReader(client), pend: map[int]chan cdpReply{}, done: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, _, err := w.call(ctx, "Runtime.evaluate", nil); err == nil {
		t.Fatal("call to a silent peer reported no error")
	}
	w.pendMu.Lock()
	left := len(w.pend)
	w.pendMu.Unlock()
	if left != 0 {
		t.Fatalf("%d pending calls leaked after a timeout", left)
	}
}

// A body above the cap used to be cut silently, so an oversized /json/list
// surfaced as "unexpected end of JSON input" instead of naming the limit.
func TestCdpGetRefusesOversizedBody(t *testing.T) {
	old := cdpMaxBody
	cdpMaxBody = 64
	t.Cleanup(func() { cdpMaxBody = old })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 200)))
	}))
	defer srv.Close()
	_, err := cdpGet(context.Background(), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "over 64 bytes") {
		t.Fatalf("err = %v, want a body-size refusal naming the 64 byte cap", err)
	}
}

// --- a fake DevTools endpoint: HTTP discovery + one WebSocket session ---

const wsAcceptGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func writeServerFrame(w io.Writer, op byte, payload []byte) error {
	hdr := []byte{0x80 | op}
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, byte(n))
	case n <= 0xffff:
		hdr = append(hdr, 126, byte(n>>8), byte(n))
	default:
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		hdr = append(hdr, 127)
		hdr = append(hdr, ext[:]...)
	}
	_, err := w.Write(append(hdr, payload...))
	return err
}

func readClientFrame(br *bufio.Reader) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(br, h[:]); err != nil {
		return nil, err
	}
	n := int64(h[1] & 0x7f)
	switch n {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(br, ext[:]); err != nil {
			return nil, err
		}
		n = int64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(br, ext[:]); err != nil {
			return nil, err
		}
		n = int64(binary.BigEndian.Uint64(ext[:]))
	}
	var mask [4]byte
	if h[1]&0x80 != 0 {
		if _, err := io.ReadFull(br, mask[:]); err != nil {
			return nil, err
		}
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(br, payload); err != nil {
		return nil, err
	}
	if h[1]&0x80 != 0 {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return payload, nil
}

// fakeDevtools answers /json/list and /json/version, then speaks one session:
// an event first, the answer to the client's request, and nothing else.
func fakeDevtools(t *testing.T, methods *sync.Map) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/json/list":
			fmt.Fprintf(w, `[{"id":"T1","type":"page","title":"fake page","url":"http://example.test/","webSocketDebuggerUrl":"ws://%s/devtools/page/T1"}]`, r.Host)
		case "/json/version":
			fmt.Fprint(w, `{"Browser":"Fake/1.0","Protocol-Version":"1.3"}`)
		case "/devtools/page/T1":
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Errorf("test server cannot hijack")
				return
			}
			conn, brw, err := hj.Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			defer conn.Close()
			// r is the handshake the server already parsed; brw holds only what
			// arrived after it.
			sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + wsAcceptGUID))
			accept := base64.StdEncoding.EncodeToString(sum[:])
			fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
			if err := writeServerFrame(conn, 0x1, []byte(`{"method":"Page.loadEventFired","params":{"timestamp":7}}`)); err != nil {
				t.Errorf("event frame: %v", err)
				return
			}
			body, err := readClientFrame(brw.Reader)
			if err != nil {
				t.Errorf("read request frame: %v", err)
				return
			}
			var m struct {
				ID     int    `json:"id"`
				Method string `json:"method"`
			}
			if err := json.Unmarshal(body, &m); err != nil {
				t.Errorf("request frame is not JSON: %v", err)
				return
			}
			if methods != nil {
				methods.Store(m.Method, true)
			}
			reply := fmt.Sprintf(`{"id":%d,"result":{"result":{"type":"number","value":42}}}`, m.ID)
			if err := writeServerFrame(conn, 0x1, []byte(reply)); err != nil {
				t.Errorf("reply frame: %v", err)
				return
			}
			_, _ = io.Copy(io.Discard, brw)
		default:
			http.NotFound(w, r)
		}
	}))
}

// The whole driver against a local endpoint: two discovery GETs, one attach,
// one step, one collected event. No browser, no node.
func TestCdpRunSessionRoundTrip(t *testing.T) {
	var methods sync.Map
	srv := fakeDevtools(t, &methods)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := cdpRun(ctx, webSpec{
		Endpoint: srv.Listener.Addr().String(),
		Mode:     "session",
		Steps:    []webStep{{Method: "Runtime.evaluate", Params: map[string]any{"expression": "1+1"}}},
		Collect:  &webCollect{Ms: 120, Prefixes: []string{"Page."}},
	})
	if err != nil {
		t.Fatalf("cdpRun: %v", err)
	}
	if len(out.Targets) != 1 || out.Targets[0].ID != "T1" {
		t.Fatalf("targets = %+v, want the one fake page", out.Targets)
	}
	if out.Target == nil || out.Target.ID != "T1" || out.Target.WS == "" {
		t.Fatalf("attached target = %+v", out.Target)
	}
	if got := str(out.Version["Browser"]); got != "Fake/1.0" {
		t.Fatalf("version browser = %q, want Fake/1.0", got)
	}
	if len(out.Steps) != 1 || !out.Steps[0].Ok || num(out.Steps[0].Result["result"].(map[string]any)["value"]) != 42 {
		t.Fatalf("steps = %+v, want one ok Runtime.evaluate answering 42", out.Steps)
	}
	if _, ok := methods.Load("Runtime.evaluate"); !ok {
		t.Fatalf("the endpoint never saw Runtime.evaluate")
	}
	if len(out.Events) != 1 || out.Events[0].Method != "Page.loadEventFired" {
		t.Fatalf("events = %+v, want the Page.loadEventFired event the prefix asks for", out.Events)
	}
}

// The URL in cdpRun must never point off-box, even when a caller bypasses webTarget.
func TestCdpRunRefusesRemoteEndpoint(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := cdpRun(ctx, webSpec{Endpoint: "8.8.8.8:9222", Mode: "list"})
	if err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("remote endpoint err = %v, want a loopback refusal", err)
	}
}

// Negative path 1: the port answers, but not with a target list.
func TestCdpRunNegativeListUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not here", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := cdpRun(ctx, webSpec{Endpoint: srv.Listener.Addr().String(), Mode: "list"})
	if err == nil || !strings.Contains(err.Error(), "/json/list: 503 Service Unavailable") {
		t.Fatalf("err = %v, want the /json/list status to be named", err)
	}
}

// Negative path 2: the port answers 200 with something that is not a target
// array, and a session attach with no attachable target is refused.
func TestCdpRunNegativeShape(t *testing.T) {
	list := func(body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/json/list":
				fmt.Fprint(w, body)
			case "/json/version":
				fmt.Fprint(w, `{}`)
			}
		}))
	}
	notArray := list(`{"targets":[]}`)
	defer notArray.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := cdpRun(ctx, webSpec{Endpoint: notArray.Listener.Addr().String(), Mode: "list"}); err == nil || !strings.Contains(err.Error(), "returned no target array") {
		t.Fatalf("err = %v, want the non-array body to be named", err)
	}
	// No webSocketDebuggerUrl: reachable, but nothing to attach to.
	noWS := list(`[{"id":"T1","type":"page","url":"http://example.test/"}]`)
	defer noWS.Close()
	if _, err := cdpRun(ctx, webSpec{Endpoint: noWS.Listener.Addr().String(), Mode: "session"}); err == nil || !strings.Contains(err.Error(), "no attachable target") {
		t.Fatalf("err = %v, want no attachable target", err)
	}
}

// A $ref must resolve from the steps already run and stay absent when it does
// not resolve; $target.url feeds the two URL shortcuts.
func TestCdpDerefAndQuoteMeta(t *testing.T) {
	out := webOut{
		Target: &webTargetRow{URL: "http://a.test/x?y=1"},
		Steps:  []webStepResult{{Method: "a", Ok: true, Result: map[string]any{"result": map[string]any{"value": 7}}}},
	}
	if got := cdpDeref(out, "$0.result.value"); got != 7 {
		t.Fatalf("$0.result.value = %v, want 7", got)
	}
	if got := cdpDeref(out, "$0.result"); got == nil {
		t.Fatal("$0.result resolved to nil")
	}
	if got := cdpDeref(out, "$9.result"); got != nil {
		t.Fatalf("out-of-range $9 = %v, want nil", got)
	}
	if got := cdpDeref(out, "$target.urlQuote"); got != `http://a\.test/x\?y=1` {
		t.Fatalf("$target.urlQuote = %v", got)
	}
	if got := cdpDeref(out, "plain"); got != "plain" {
		t.Fatalf("literal = %v", got)
	}
	if got := cdpQuoteMeta("a+b(c)"); got != `a\+b\(c\)` {
		t.Fatalf("quoteMeta = %q", got)
	}
}

// The target order is the driver's: an explicit id, then the first page, then
// whatever came first; an empty list is a refusal, not a silent attach.
func TestCdpPickTargetOrder(t *testing.T) {
	targets := []webTargetRow{
		{ID: "A", Type: "service_worker", WS: "ws://a"},
		{ID: "B", Type: "page", WS: "ws://b"},
	}
	if got, err := cdpPickTarget(targets, map[string]any{"id": "A"}); err != nil || got.ID != "A" {
		t.Fatalf("explicit id = %+v (%v)", got, err)
	}
	if got, err := cdpPickTarget(targets, nil); err != nil || got.ID != "B" {
		t.Fatalf("default type = %+v (%v), want the page", got, err)
	}
	if got, err := cdpPickTarget(targets, map[string]any{"id": "Z"}); err != nil || got.ID != "B" {
		t.Fatalf("unknown id = %+v (%v), want the documented fallback", got, err)
	}
	if _, err := cdpPickTarget(nil, nil); err == nil {
		t.Fatal("an empty target list was attachable")
	}
}
