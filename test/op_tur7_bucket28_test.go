package main

// Tur 7 bucket 28: the shipped skill doc is a promise to the user, the binary
// is the product. Existing tests pin the registry against testdata/ops.json
// (our own table); none reads the skill's op table. This test closes that gap:
// every op the doc advertises must be registered here and accepted by the CLI,
// and every registered op must be advertised. The doc is read-only input.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const tur7SkillRefs = "../skill/references"

var (
	tur7HeadlineRe = regexp.MustCompile(`# Op smoke table — ([0-9]+) ops`)
	tur7RouteRe    = regexp.MustCompile(`^\| ([LYG]) [^|]*\| ([0-9]+) \|`)
	tur7TotalRe    = regexp.MustCompile(`^\| \*\*Total\*\* \| ([0-9]+) \|`)
)

func TestTur7Bucket28OpDocParity(t *testing.T) {
	if buildErr != nil {
		t.Fatalf("go build failed: %v\n%s", buildErr, buildLog)
	}
	if cliPath == "" {
		t.Fatal("cli binary was not built")
	}

	docNames, docRoute, docCells, headline, docTotal, docRoutes := tur7ReadOpDocs(t)

	// Registry: the real map ops.go declares and every op file registers into.
	registered := opNames()
	if len(registered) != len(ops) {
		t.Fatalf("opNames returned %d names for a %d-entry registry", len(registered), len(ops))
	}
	for _, n := range registered {
		if o := ops[n]; o.name != n {
			t.Fatalf("op registered under %q carries name %q", n, o.name)
		}
	}

	// The doc's own arithmetic must hold before it can be compared to code.
	cellSum := 0
	for _, c := range docCells {
		if c.count != len(c.ops) {
			t.Fatalf("doc cell %s/%s claims count %d but lists %d ops: %v", c.route, c.bucket, c.count, len(c.ops), c.ops)
		}
		cellSum += c.count
	}
	if cellSum != len(docNames) {
		t.Fatalf("doc cells sum to %d ops but name %d distinct ops", cellSum, len(docNames))
	}
	if headline != docTotal || docTotal != len(docNames) {
		t.Fatalf("doc headline %d, total row %d, named ops %d: not one number", headline, docTotal, len(docNames))
	}
	for route, want := range docRoutes {
		if got := len(tur7FilterRoutes(docRoute, route)); got != want {
			t.Fatalf("doc summary says route %s has %d ops, its cell lists name %d", route, want, got)
		}
	}

	// Set equality, both directions, before any subprocess work.
	var undocumented, unregistered []string
	for _, n := range registered {
		if _, ok := docRoute[n]; !ok {
			undocumented = append(undocumented, n)
		}
	}
	for _, n := range docNames {
		if _, ok := ops[n]; !ok {
			unregistered = append(unregistered, n)
		}
	}
	if len(undocumented) > 0 || len(unregistered) > 0 {
		t.Fatalf("registry/doc drift: %d registered op(s) the skill table does not document %v; %d documented op(s) the binary does not register %v",
			len(undocumented), undocumented, len(unregistered), unregistered)
	}

	// The binary's own inventory must be the same set the source registers.
	listDir := t.TempDir()
	stdout, stderr, rc := tur7Exec(t, listDir, tur7Env(listDir), 20*time.Second, "--list-ops")
	if rc != 0 {
		t.Fatalf("--list-ops exited %d: %s", rc, stderr)
	}
	listed := map[string]bool{}
	var listedCount int
	for _, line := range strings.Split(strings.TrimSuffix(stdout, "\n"), "\n") {
		name := strings.TrimSpace(line)
		if name == "" {
			continue
		}
		if listed[name] {
			t.Fatalf("--list-ops repeats %q", name)
		}
		listed[name] = true
		listedCount++
	}
	var onlyBinary, onlySource []string
	for _, n := range registered {
		if !listed[n] {
			onlySource = append(onlySource, n)
		}
	}
	for n := range listed {
		if _, ok := ops[n]; !ok {
			onlyBinary = append(onlyBinary, n)
		}
	}
	sort.Strings(onlyBinary)
	if len(onlyBinary) > 0 || len(onlySource) > 0 || listedCount != len(registered) {
		t.Fatalf("--list-ops disagrees with the registry: %d listed vs %d registered; only in binary %v; only in source %v",
			listedCount, len(registered), onlyBinary, onlySource)
	}

	// Every documented op must be dispatched, not merely listed: an op the
	// binary calls "unknown op" is not shipped however nicely it is documented.
	root := t.TempDir()
	for _, name := range docNames {
		dir := filepath.Join(root, name)
		state := filepath.Join(root, "state-"+name)
		for _, p := range []string{dir, state} {
			if err := os.MkdirAll(p, 0o755); err != nil {
				t.Fatalf("mkdir %s: %v", p, err)
			}
		}
		out, errOut, code := tur7Exec(t, dir, tur7Env(state), 20*time.Second, "--op", name)
		combined := out + errOut
		if strings.Contains(strings.ToLower(combined), "unknown op") {
			t.Errorf("documented op %q is unknown to the binary (exit %d): %s", name, code, strings.TrimSpace(combined))
			continue
		}
		switch code {
		case 0:
			var doc struct {
				Op     string          `json:"op"`
				Result json.RawMessage `json:"result"`
			}
			if err := json.Unmarshal([]byte(out), &doc); err != nil {
				t.Errorf("documented op %q exited 0 without an envelope: %v: %s", name, err, strings.TrimSpace(out))
				continue
			}
			if doc.Op != name {
				t.Errorf("documented op %q answered under envelope op %q", name, doc.Op)
			}
			var obj map[string]any
			if len(doc.Result) == 0 || json.Unmarshal(doc.Result, &obj) != nil || obj == nil {
				t.Errorf("documented op %q exited 0 with no result object: %s", name, strings.TrimSpace(out))
			}
		case 2:
			var env struct {
				Kind  string `json:"kind"`
				Error string `json:"error"`
			}
			if err := json.Unmarshal([]byte(out), &env); err != nil || env.Kind == "" {
				t.Errorf("documented op %q refused without a kind envelope: stdout=%q stderr=%q", name, strings.TrimSpace(out), strings.TrimSpace(errOut))
				continue
			}
			if !tur7KindKnown(env.Kind) {
				t.Errorf("documented op %q refused with kind %q outside kindList", name, env.Kind)
			}
			if env.Error == "" {
				t.Errorf("documented op %q refused with kind %q but no error text", name, env.Kind)
			}
		default:
			t.Errorf("documented op %q exited %d, want 0 (answer) or 2 (refusal): %s", name, code, strings.TrimSpace(combined))
		}
	}
}

type tur7DocCell struct {
	route, bucket string
	count         int
	ops           []string
}

// tur7ReadOpDocs parses the skill's generated op table pair: op-table.md carries
// the headline, route summary and bucket matrix; op-table-list.md carries the
// cell name lists. It fails on any shape it cannot read: a doc this test cannot
// parse must never be treated as agreement.
func tur7ReadOpDocs(t *testing.T) (names []string, route map[string]string, cells []tur7DocCell, headline, total int, routeTotals map[string]int) {
	t.Helper()
	tableBytes, err := os.ReadFile(filepath.Join(tur7SkillRefs, "op-table.md"))
	if err != nil {
		t.Fatalf("read skill op table: %v", err)
	}
	listBytes, err := os.ReadFile(filepath.Join(tur7SkillRefs, "op-table-list.md"))
	if err != nil {
		t.Fatalf("read skill op table cell list: %v", err)
	}

	table := string(tableBytes)
	if m := tur7HeadlineRe.FindStringSubmatch(table); m == nil {
		t.Fatal("op-table.md has no '# Op smoke table — N ops' headline")
	} else if headline, err = strconv.Atoi(m[1]); err != nil {
		t.Fatalf("op-table.md headline is not a number: %v", err)
	}
	routeTotals = map[string]int{}
	for _, line := range strings.Split(table, "\n") {
		if m := tur7RouteRe.FindStringSubmatch(line); m != nil {
			n, err := strconv.Atoi(m[2])
			if err != nil {
				t.Fatalf("op-table.md route %s count %q: %v", m[1], m[2], err)
			}
			routeTotals[m[1]] = n
		}
		if m := tur7TotalRe.FindStringSubmatch(line); m != nil {
			if total, err = strconv.Atoi(m[1]); err != nil {
				t.Fatalf("op-table.md total %q: %v", m[1], err)
			}
		}
	}
	if len(routeTotals) != 3 {
		t.Fatalf("op-table.md summary names %d routes, want L/Y/G: %v", len(routeTotals), routeTotals)
	}
	if total == 0 {
		t.Fatal("op-table.md has no '**Total**' row")
	}

	inTSV := false
	route = map[string]string{}
	for _, line := range strings.Split(string(listBytes), "\n") {
		switch {
		case strings.HasPrefix(line, "```tsv"):
			inTSV = true
			continue
		case inTSV && strings.HasPrefix(line, "```"):
			inTSV = false
			continue
		case !inTSV:
			continue
		}
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 || fields[3] == "ops" {
			continue
		}
		if fields[0] != "L" && fields[0] != "Y" && fields[0] != "G" {
			t.Fatalf("op-table-list.md row with route %q: %q", fields[0], line)
		}
		count, err := strconv.Atoi(fields[2])
		if err != nil {
			t.Fatalf("op-table-list.md cell %s/%s count %q: %v", fields[0], fields[1], fields[2], err)
		}
		cell := tur7DocCell{route: fields[0], bucket: fields[1], count: count}
		if fields[3] != "-" {
			cell.ops = strings.Split(fields[3], ",")
		}
		for _, n := range cell.ops {
			if n == "" {
				t.Fatalf("op-table-list.md cell %s/%s has an empty op name", cell.route, cell.bucket)
			}
			if prev, dup := route[n]; dup {
				t.Fatalf("op %q documented twice (routes %s and %s)", n, prev, cell.route)
			}
			route[n] = cell.route
		}
		cells = append(cells, cell)
	}
	if !inTSV && len(cells) == 0 {
		t.Fatal("op-table-list.md has no ```tsv cell block")
	}
	if len(cells) == 0 {
		t.Fatal("op-table-list.md tsv block lists no cells")
	}
	for n := range route {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, route, cells, headline, total, routeTotals
}

func tur7FilterRoutes(route map[string]string, want string) []string {
	var out []string
	for n, r := range route {
		if r == want {
			out = append(out, n)
		}
	}
	return out
}

func tur7KindKnown(kind string) bool {
	for _, k := range kindList {
		if string(k) == kind {
			return true
		}
	}
	return false
}

// tur7Env is a hermetic child environment: no LRECON_* input from the
// developer's shell, state under the test's temp dir, adb pointed at a closed
// port so device ops take their no-device branch instead of reading a phone.
func tur7Env(stateDir string) []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "LRECON_") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, "LRECON_STATE="+stateDir, "ADB_SERVER_SOCKET=tcp:127.0.0.1:1")
}

func tur7Exec(t *testing.T, dir string, env []string, timeout time.Duration, args ...string) (stdout, stderr string, rc int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, cliPath, args...)
	cmd.Dir = dir
	cmd.Env = env
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("%v timed out after %s", args, timeout)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		rc = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run %v: %v", args, err)
	}
	return out.String(), errb.String(), rc
}
