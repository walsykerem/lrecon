package main

// Tur 7 / bucket 22: the procedure graph the Ghidra-backed ops of this slice
// report must be a graph, not a pile of independent answers. For every
// procedure in a bounded subgraph reachable from the entry, the edge list
// procedure_callees returns and the edge list procedure_callers returns for
// the other endpoint have to agree (no edge that exists in one direction
// only), procedure_info has to answer with exactly the address that was used
// to ask, and the entry's out-edges have to match an independent objdump
// decode of the same bytes.
//
// The subgraph is the entry plus its direct callees. Every additional node
// costs another analyzeHeadless pass, so the closure claim is stated over that
// set and the test asserts the set's size instead of wandering further.

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	tur22Fixture   = "testdata/fixtures/elf"
	tur22EntryName = "FUN_00401000"
)

type tur22Edge struct {
	Address uint64
	Name    string
}

// tur22Map runs one op and decodes the same JSON the CLI prints.
func tur22Map(t *testing.T, op, at, name string) map[string]any {
	t.Helper()
	t.Setenv("LRECON_AT", at)
	t.Setenv("LRECON_NAME", name)
	raw, err := runOp(op, tur22Fixture)
	if err != nil {
		t.Fatalf("%s (LRECON_AT=%q, LRECON_NAME=%q): %v", op, at, name, err)
	}
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("%s: marshal: %v", op, err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: answer is not a JSON object (%s): %v", op, b, err)
	}
	return m
}

func tur22Addr(t *testing.T, label string, v any) uint64 {
	t.Helper()
	s, ok := v.(string)
	if !ok {
		t.Fatalf("%s: address field %v is not a string", label, v)
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
	if err != nil {
		t.Fatalf("%s: address %q is not hex: %v", label, s, err)
	}
	return n
}

func tur22Hex(at uint64) string { return fmt.Sprintf("0x%x", at) }

func tur22Str(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	s, ok := m[key].(string)
	if !ok || s == "" {
		t.Fatalf("%s = %v (%T), want a non-empty string; full answer %v", key, m[key], m[key], m)
	}
	return s
}

// tur22Edges decodes an edges list: the count field must describe the list,
// every edge must carry a name that names its own address, and no address may
// appear twice.
func tur22Edges(t *testing.T, label string, m map[string]any) []tur22Edge {
	t.Helper()
	raw, ok := m["edges"].([]any)
	if !ok {
		t.Fatalf("%s: edges = %v (%T), want an array; answer %v", label, m["edges"], m["edges"], m)
	}
	// count is the true total; a huge caller list is truncated to a sample, so
	// count may exceed the edges actually shipped.
	if n, ok := m["count"].(float64); !ok || int(n) < len(raw) {
		t.Fatalf("%s: count = %v but %d edges: the answer disagrees with itself", label, m["count"], len(raw))
	}
	seen := make(map[uint64]bool, len(raw))
	out := make([]tur22Edge, 0, len(raw))
	for _, e := range raw {
		em, ok := e.(map[string]any)
		if !ok {
			t.Fatalf("%s: edge %v is not an object", label, e)
		}
		at := tur22Addr(t, label+" edge entry", em["entry"])
		name, _ := em["name"].(string)
		if name == "" {
			t.Fatalf("%s: edge %#x has no name", label, at)
		}
		if strings.HasPrefix(name, "FUN_") {
			n, err := strconv.ParseUint(strings.TrimPrefix(name, "FUN_"), 16, 64)
			if err != nil || n != at {
				t.Fatalf("%s: %q names %s but the edge entry is %#x", label, name, strings.TrimPrefix(name, "FUN_"), at)
			}
		}
		if seen[at] {
			t.Fatalf("%s: address %#x appears twice in one edge list", label, at)
		}
		seen[at] = true
		out = append(out, tur22Edge{Address: at, Name: name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out
}

func tur22Has(edges []tur22Edge, at uint64) bool {
	for _, e := range edges {
		if e.Address == at {
			return true
		}
	}
	return false
}

type tur22Insn struct {
	at, end uint64
	mnem    string
	operand string
}

var tur22ObjdumpLine = regexp.MustCompile(`^ +([0-9a-f]+): +([0-9a-f ]*)\t(.*)$`)

// tur22Disasm is the independent decoder: objdump on the same file, no lrecon
// code involved. lo/hi bound the window; zero means the whole file.
func tur22Disasm(t *testing.T, path string, lo, hi uint64) []tur22Insn {
	t.Helper()
	bin, err := exec.LookPath("objdump")
	if err != nil {
		t.Fatalf("objdump not available, cannot cross-check Ghidra's edges: %v", err)
	}
	args := []string{"-d"}
	if lo != 0 || hi != 0 {
		args = append(args, fmt.Sprintf("--start-address=%s", tur22Hex(lo)), fmt.Sprintf("--stop-address=%s", tur22Hex(hi)))
	}
	out, err := exec.Command(bin, append(args, path)...).Output()
	if err != nil {
		t.Fatalf("objdump %v: %v", args, err)
	}
	var ins []tur22Insn
	for _, line := range strings.Split(string(out), "\n") {
		f := tur22ObjdumpLine.FindStringSubmatch(line)
		if f == nil {
			continue
		}
		at, err := strconv.ParseUint(f[1], 16, 64)
		if err != nil {
			continue
		}
		size := uint64(len(strings.Fields(f[2])))
		body := f[3]
		mnem, operand := body, ""
		if i := strings.IndexByte(body, '\t'); i >= 0 {
			mnem, operand = body[:i], body[i+1:]
		}
		ins = append(ins, tur22Insn{at: at, end: at + size, mnem: strings.TrimSpace(mnem), operand: strings.TrimSpace(operand)})
	}
	if len(ins) == 0 {
		t.Fatalf("objdump decoded nothing from %s", path)
	}
	return ins
}

func tur22CallTargets(ins []tur22Insn) map[uint64]bool {
	calls := map[uint64]bool{}
	for _, i := range ins {
		if i.mnem != "call" && i.mnem != "callq" && i.mnem != "calll" {
			continue
		}
		tok := strings.Fields(i.operand)
		if len(tok) == 0 || !strings.HasPrefix(tok[0], "0x") {
			continue
		}
		if at, err := strconv.ParseUint(tok[0][2:], 16, 64); err == nil {
			calls[at] = true
		}
	}
	return calls
}

func TestTur7Bucket22ProcedureGraph(t *testing.T) {
	requireRealGhidra(t)
	fixture, err := filepath.Abs(tur22Fixture)
	if err != nil {
		t.Fatalf("fixture path: %v", err)
	}

	// 1. procedure_info: the name and the address are two ways to ask about one
	//    procedure, and the answer has to be the same one either way — the entry
	//    it reports must be the address that produced the answer.
	byName := tur22Map(t, "procedure_info", "", tur22EntryName)
	entry := tur22Addr(t, "procedure_info(NAME) entry", byName["entry"])
	byAddr := tur22Map(t, "procedure_info", tur22Hex(entry), "")
	if got := tur22Addr(t, "procedure_info(AT) entry", byAddr["entry"]); got != entry {
		t.Fatalf("procedure_info(AT %#x) answered entry %#x: the address it was asked about is not the address it reports", entry, got)
	}
	for _, key := range []string{"function", "signature", "size"} {
		if fmt.Sprint(byName[key]) != fmt.Sprint(byAddr[key]) {
			t.Fatalf("procedure_info(%s) = %v but procedure_info(0x%x) = %v: the same procedure got two answers",
				key, byName[key], entry, byAddr[key])
		}
	}
	if got := tur22Str(t, byName, "function"); got != tur22EntryName {
		t.Fatalf("procedure_info(NAME=%s).function = %q", tur22EntryName, got)
	}
	size, ok := byAddr["size"].(float64)
	if !ok || size <= 0 {
		t.Fatalf("procedure_info.size = %v, want a positive byte count", byAddr["size"])
	}

	// 2. Independent decode of exactly the bytes procedure_info claims belong to
	//    the entry: first instruction at the entry, last one ending at the
	//    claimed end, and the call instructions there are the callee list.
	span := tur22Disasm(t, fixture, entry, entry+uint64(size))
	if span[0].at != entry {
		t.Fatalf("objdump's first instruction in [%#x,%#x) is at %#x", entry, entry+uint64(size), span[0].at)
	}
	if got := span[len(span)-1].end; got != entry+uint64(size) {
		t.Fatalf("objdump's last instruction ends at %#x, procedure_info claims %#x (size %v)", got, entry+uint64(size), size)
	}
	objdumpCalls := tur22CallTargets(span)

	callees := tur22Edges(t, "procedure_callees(entry)", tur22Map(t, "procedure_callees", tur22Hex(entry), ""))
	if len(callees) == 0 {
		t.Fatalf("procedure_callees(%#x) is empty while objdump sees %d call targets in the same span", entry, len(objdumpCalls))
	}
	if len(objdumpCalls) != len(callees) {
		t.Fatalf("objdump decoded %d call targets in [%#x,%#x), procedure_callees reports %d callees",
			len(objdumpCalls), entry, entry+uint64(size), len(callees))
	}
	for _, e := range callees {
		if !objdumpCalls[e.Address] {
			t.Fatalf("procedure_callees(%#x) reports edge to %#x (%s) but no call instruction in [%#x,%#x) targets it",
				entry, e.Address, e.Name, entry, entry+uint64(size))
		}
	}

	// 3. Closure over the reachable set: the entry plus its direct callees. Each
	//    address that appeared in an edge must be a procedure of its own, asked
	//    for by that address, and every internal edge must exist in both
	//    directions.
	visited := map[uint64]string{entry: tur22EntryName}
	nodes := []uint64{entry}
	for _, e := range callees {
		visited[e.Address] = e.Name
		nodes = append(nodes, e.Address)
	}
	callersOf := map[uint64][]tur22Edge{}
	calleesOf := map[uint64][]tur22Edge{}
	for _, at := range nodes {
		info := tur22Map(t, "procedure_info", tur22Hex(at), "")
		if got := tur22Addr(t, "procedure_info entry", info["entry"]); got != at {
			t.Fatalf("procedure_info(AT %#x) answered entry %#x: procedure_info's address is not the one that produced it", at, got)
		}
		if got := tur22Str(t, info, "function"); got != visited[at] {
			t.Fatalf("procedure_info(AT %#x).function = %q but the edge that led here named it %q", at, got, visited[at])
		}
		calleesOf[at] = tur22Edges(t, "procedure_callees("+tur22Hex(at)+")", tur22Map(t, "procedure_callees", tur22Hex(at), ""))
		callersOf[at] = tur22Edges(t, "procedure_callers("+tur22Hex(at)+")", tur22Map(t, "procedure_callers", tur22Hex(at), ""))
	}

	// Every edge the entry claims must be visible from the callee's side.
	for _, e := range calleesOf[entry] {
		if !tur22Has(callersOf[e.Address], entry) {
			t.Fatalf("dangling edge: procedure_callees(%#x) lists %#x (%s) but procedure_callers(%#x) does not list %#x back",
				entry, e.Address, e.Name, e.Address, entry)
		}
	}
	// And every edge seen from a caller's side must exist from the callee's
	// side too. Callers outside the visited set are not followed: each one
	// would need its own analyzeHeadless pass.
	internal := 0
	for _, at := range nodes {
		for _, e := range callersOf[at] {
			caller, ok := visited[e.Address]
			if !ok {
				continue
			}
			internal++
			if !tur22Has(calleesOf[e.Address], at) {
				t.Fatalf("dangling edge: procedure_callers(%#x) lists caller %#x (%s) but procedure_callees(%#x) does not list %#x back",
					at, e.Address, caller, e.Address, at)
			}
		}
	}
	if internal != len(calleesOf[entry]) {
		t.Fatalf("closed subgraph has %d internal caller edges but the entry's callee list has %d edges: some entry edge is not reciprocal",
			internal, len(calleesOf[entry]))
	}

	// 4. prev_address walks the same procedure graph backwards over the session
	//    document; every hop's "to" must be a real instruction start in the
	//    binary (objdump), strictly below the cursor it came from, and the walk
	//    must be exactly undone by next_address.
	t.Setenv("LRECON_STATE", t.TempDir())
	t.Setenv("LRECON_SESSION", "")
	startAt := uint64(0x444560)
	t.Setenv("LRECON_AT", tur22Hex(startAt))
	if _, err := runOp("binary_session", tur22Fixture); err != nil {
		t.Fatalf("binary_session: %v", err)
	}
	gotoRaw, err := runOp("goto_address", tur22Fixture)
	if err != nil {
		t.Fatalf("goto_address(%#x): %v", tur22Hex(startAt), err)
	}
	var gotoAnswer map[string]any
	if b, err := json.Marshal(gotoRaw); err == nil {
		_ = json.Unmarshal(b, &gotoAnswer)
	}
	startName := tur22Str(t, gotoAnswer, "procedure")

	first := tur22Map(t, "prev_address", "", "")
	if first["found"] != true {
		t.Fatalf("prev_address reported no predecessor of %#x: %v", startAt, first)
	}
	if _, ok := first["found"].(bool); !ok {
		t.Fatalf("prev_address.found is not a boolean: %v", first["found"])
	}
	from := tur22Addr(t, "prev_address from", first["from"])
	to := tur22Addr(t, "prev_address to", first["to"])
	if from != startAt {
		t.Fatalf("prev_address.from = %#x, want the cursor %#x", from, startAt)
	}
	if to >= from {
		t.Fatalf("prev_address moved forward: %#x -> %#x", from, to)
	}

	decoded := map[uint64]bool{}
	for _, ins := range tur22Disasm(t, fixture, 0, 0) {
		decoded[ins.at] = true
	}
	for _, at := range []uint64{from, to} {
		if !decoded[at] {
			t.Fatalf("%#x is not the start of a decoded instruction in %s", at, tur22Fixture)
		}
	}

	// The inverse walk has to come back to the exact same procedures.
	next := tur22Map(t, "next_address", "", "")
	if next["found"] != true {
		t.Fatalf("next_address found nothing after %#x: %v", to, next)
	}
	if back := tur22Addr(t, "next_address from", next["from"]); back != to {
		t.Fatalf("next_address.from = %#x, want the address prev_address left the cursor at (%#x)", back, to)
	}
	if back := tur22Addr(t, "next_address to", next["to"]); back != from {
		t.Fatalf("prev_address moved %#x -> %#x but next_address moved %#x -> %#x: the two edges are not inverses",
			from, to, to, back)
	}
	if got := tur22Str(t, next, "procedure"); got != startName {
		t.Fatalf("goto_address(%#x) named %q but the prev/next round trip named %q: one procedure, two names",
			startAt, startName, got)
	}
}
