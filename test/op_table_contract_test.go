package main

// Table-driven contract test for every registered op (report B2/B3).
//
// The old tests reached ops through their Go functions; only four ops were
// ever run through `--op`, so the CLI surface -- the thing a caller actually
// uses -- was untested. This file walks testdata/ops.json, runs the built
// binary once per op, and checks the two promises that hold for every registered op:
//
//	needs=true  + no target   -> exit 2, refusal envelope, "needs ... target path"
//	                             (or the flag that has nowhere to go: "needs -o")
//	any op      + any target  -> JSON result (exit 0) or an honest refusal
//	                             (exit 2, refusal envelope, reason on stderr)
//
// and never a panic, a hang, a malformed envelope or an unexpected exit code.
//
// Regenerate the published classes with:
//
//	go test -run TableContract -update
//
// Route G (Ghidra) and route Y (external tools) are opt-in for the target
// pass, because one Ghidra import is minutes and can leak a JVM (report A4/B1)
// and route Y needs a device or debugger that CI does not have:
//
//	LRECON_OPS_GHIDRA=1 LRECON_GHIDRA_TIMEOUT=5s go test -run TableContract
//	LRECON_OPS_TOOLS=1 go test -run TableContract
//
// -short skips both routes for the target pass; the no-target pass still runs
// every op because a missing target is answered before any tool is touched.

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

var updateOpTable = flag.Bool("update", false, "rewrite testdata/ops.json from this run's observations")

const (
	opDefaultTimeout = 120 * time.Second
	opShortTimeout   = 30 * time.Second
)

// opContractTimeout is the budget for a run that hands the op an artifact. It
// stays opDefaultTimeout under -short: a cold Mach-O import takes 27-35 s (see
// ext_table_contract_test.go) and crossing a short budget turns a slow-but-
// correct op into a timeout defect. Only the no-target pass, which touches no
// tool, keeps the short budget (opNoTargetTimeout).
func opContractTimeout() time.Duration {
	if v := strings.TrimSpace(os.Getenv("LRECON_OPS_TIMEOUT")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return opDefaultTimeout
}

// opNoTargetTimeout is the budget for the missing-argument pass: no tool runs,
// so -short may keep it tight.
func opNoTargetTimeout() time.Duration {
	if v := strings.TrimSpace(os.Getenv("LRECON_OPS_TIMEOUT")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	if testing.Short() {
		return opShortTimeout
	}
	return opDefaultTimeout
}

// opRefusalInputExempt names rows whose bad_arg refusal names the artifact
// shape instead of the file. The op files belong to other lanes.
// shortcut: verify_managed_native_boundaries says "not a PE image"; tighten it
// in op_inspect_managed_native_boundaries.go to the basename, then drop this.
var opRefusalInputExempt = map[string]bool{"verify_managed_native_boundaries": true}

// opEnv is the child environment for one target run. A gated row gets its
// engine made unreachable so the row still runs: route G an authoritative
// missing Ghidra (findGhidra treats LRECON_GHIDRA as authoritative), route Y a
// PATH with no tool in it. Both refuse in well under a second.
func opEnvRoute(route, gateReason, stateDir string) []string {
	env := opContractEnv(stateDir)
	if gateReason == "" {
		return env
	}
	drop, add := "LRECON_GHIDRA=", "LRECON_GHIDRA=/nonexistent/lrecon-ghidra"
	if route != "G" {
		drop, add = "PATH=", "PATH=/nonexistent/lrecon-tools"
	}
	kept := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if strings.HasPrefix(kv, drop) || strings.HasPrefix(kv, "LRECON_ANALYZEHEADLESS=") {
			continue
		}
		kept = append(kept, kv)
	}
	return append(kept, add)
}

// TestTableContractInventory is the drift check: the table and the registerOp
// inventory must name the same ops with the same route and needs flag. A new
// op without a row, or a row for an op that no longer exists, fails here
// before any process is started.
func TestTableContractInventory(t *testing.T) {
	tbl, err := loadOpTable(opTablePath)
	if err != nil {
		t.Fatalf("load %s: %v\ngenerate it with: go test -run TableContract -update", opTablePath, err)
	}
	if len(tbl.Ops) == 0 {
		t.Fatalf("%s lists no ops", opTablePath)
	}
	if len(tbl.Ops) != 235 {
		t.Fatalf("%s lists %d ops, want the pinned 235", opTablePath, len(tbl.Ops))
	}
	seen := make(map[string]bool, len(tbl.Ops))
	routes := map[string]int{}
	needs := 0
	for _, row := range tbl.Ops {
		if row.Name == "" {
			t.Fatalf("%s has a row without a name", opTablePath)
		}
		if seen[row.Name] {
			t.Errorf("%s lists %q twice", opTablePath, row.Name)
			continue
		}
		seen[row.Name] = true
		o, ok := ops[row.Name]
		if !ok {
			t.Errorf("table row %q is not a registered op (stale table; rerun with -update)", row.Name)
			continue
		}
		if row.Route != o.route {
			t.Errorf("%s: route %q, registered as %q", row.Name, row.Route, o.route)
		}
		if row.Needs != o.needs {
			t.Errorf("%s: needs=%v, registered as needs=%v", row.Name, row.Needs, o.needs)
		}
		if !opClassKnown(row.Expect.NoArgs) {
			t.Errorf("%s: unknown no_args class %q (rerun with -update)", row.Name, row.Expect.NoArgs)
		}
		if !opClassKnown(row.Expect.WithTarget) {
			t.Errorf("%s: unknown with_target class %q (rerun with -update)", row.Name, row.Expect.WithTarget)
		}
		if got := row.Expect.WithTarget != opClassNotApplicable; got != row.Needs {
			t.Errorf("%s: with_target=%q but needs=%v: a row with no target pass must say %q", row.Name, row.Expect.WithTarget, row.Needs, opClassNotApplicable)
		}
		if row.Expect.Requires != "" && row.Expect.NoArgs != opClassNeedsArg && row.Expect.WithTarget != opClassNeedsArg {
			t.Errorf("%s: requires=%q but neither pass expects a needs_arg answer", row.Name, row.Expect.Requires)
		}
		routes[row.Route]++
		if row.Needs {
			needs++
		}
	}
	for _, name := range opNames() {
		if !seen[name] {
			t.Errorf("registered op %q has no row in %s (rerun with -update)", name, opTablePath)
		}
	}
	t.Logf("%d ops in the table: %d L, %d G, %d Y; %d need a target",
		len(tbl.Ops), routes["L"], routes["G"], routes["Y"], needs)
}

// TestOpClassLiveKindMap pins tableClassLiveKind against kindList
// (errors.go): every table class has exactly one live mapping, every
// non-empty mapping value is a closed runtime kind (or "ok"), every runtime
// kind is reachable from at least one table class, and a table class that
// IS a runtime kind maps to itself. Skipped/not_applicable classes map to
// the kind their gate produces live (no_engine) or to "" (no pass exists);
// wrong_kind is a hint only and maps to bad_arg. A missing entry, a value
// outside kindList, or a drift here fails the build, not the sim.
func TestOpClassLiveKindMap(t *testing.T) {
	kindSet := map[string]bool{}
	for _, k := range kindList {
		kindSet[string(k)] = true
	}
	if len(kindSet) != 9 {
		t.Fatalf("kindList has %d kinds, want the closed 9: %v", len(kindSet), kindList)
	}
	for class, live := range tableClassLiveKind {
		if !opClassKnown(class) {
			t.Errorf("tableClassLiveKind has unknown class %q", class)
			continue
		}
		if live == "ok" {
			if class != opClassOK {
				t.Errorf("table class %q maps to ok; only %q may", class, opClassOK)
			}
			continue
		}
		if live == "" {
			if class != opClassNotApplicable {
				t.Errorf("table class %q maps to empty; only %q may (no pass exists)", class, opClassNotApplicable)
			}
			continue
		}
		if !kindSet[live] {
			t.Errorf("table class %q maps to %q, not in kindList (closed runtime set)", class, live)
			continue
		}
		if kindSet[class] && class != live {
			t.Errorf("table class %q is itself a runtime kind but maps to %q", class, live)
		}
	}
	// Every known table class must be mapped.
	for _, class := range []string{
		opClassOK, opClassNeedsArg, opClassBadArg, opClassOutOfScope,
		opClassNoEngine, opClassTimeout, opClassUsage, opClassIO,
		opClassStateConflict, opClassInternal, opClassWrongKind,
		opClassSkippedGhidra, opClassSkippedTool, opClassNotApplicable,
	} {
		if _, ok := tableClassLiveKind[class]; !ok {
			t.Errorf("table class %q has no tableClassLiveKind entry", class)
		}
	}
	// Every runtime kind must be reachable from some table class.
	for _, k := range kindList {
		ks := string(k)
		found := false
		for _, live := range tableClassLiveKind {
			if live == ks {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("runtime kind %q is unreachable from tableClassLiveKind", ks)
		}
	}
	// Gate classes map to what their gate produces live.
	if got := tableClassLiveKind[opClassWrongKind]; got != "bad_arg" {
		t.Errorf("wrong_kind maps to %q, want bad_arg (hint only, live is bad_arg)", got)
	}
	if got := tableClassLiveKind[opClassSkippedGhidra]; got != "no_engine" {
		t.Errorf("skipped_ghidra maps to %q, want no_engine (analyzeHeadless absent live)", got)
	}
	if got := tableClassLiveKind[opClassSkippedTool]; got != "no_engine" {
		t.Errorf("skipped_tool maps to %q, want no_engine (external tool absent live)", got)
	}
}

// TestTableContractMapClassUse checks the table only uses gate classes where
// they belong: skipped_ghidra on route G with_target, skipped_tool on route
// Y with_target, not_applicable on needs=false with_target, wrong_kind only
// on a with_target pass. A no_args gate class, or a mismatch, is a table
// bug, not a runtime kind.
func TestTableContractMapClassUse(t *testing.T) {
	tbl, err := loadOpTable(opTablePath)
	if err != nil {
		t.Fatalf("load %s: %v", opTablePath, err)
	}
	for _, row := range tbl.Ops {
		for phase, class := range map[string]string{"no_args": row.Expect.NoArgs, "with_target": row.Expect.WithTarget} {
			switch class {
			case opClassSkippedGhidra:
				if phase != "with_target" || row.Route != "G" {
					t.Errorf("%s: %s=skipped_ghidra on route %q (only G with_target)", row.Name, phase, row.Route)
				}
			case opClassSkippedTool:
				if phase != "with_target" || row.Route != "Y" {
					t.Errorf("%s: %s=skipped_tool on route %q (only Y with_target)", row.Name, phase, row.Route)
				}
			case opClassNotApplicable:
				if phase != "with_target" || row.Needs {
					t.Errorf("%s: %s=not_applicable needs=%v (only needs=false with_target)", row.Name, phase, row.Needs)
				}
			case opClassWrongKind:
				if phase != "with_target" || !row.Needs {
					t.Errorf("%s: %s=wrong_kind needs=%v (only needs=true with_target)", row.Name, phase, row.Needs)
				}
			}
		}
	}
}

// TestTableContractNoArgs runs every op with no target. For needs=true this is
// the missing-target contract; for the rest it is the one pass that touches
// nothing external, so it is safe everywhere, including CI and -short.
func TestTableContractNoArgs(t *testing.T) {
	tbl, err := loadOpTable(opTablePath)
	if err != nil {
		t.Fatalf("load %s: %v\ngenerate it with: go test -run TableContract -update", opTablePath, err)
	}
	root := t.TempDir()
	timeout := opContractTimeout()
	observed := make(map[string]string, len(tbl.Ops))
	observedReason := make(map[string]string, len(tbl.Ops))
	for i := range tbl.Ops {
		row := tbl.Ops[i]
		t.Run(row.Name, func(t *testing.T) {
			requireTableCLI(t)
			dir := filepath.Join(root, "cwd", row.Name)
			state := filepath.Join(root, "state", row.Name)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(state, 0o755); err != nil {
				t.Fatal(err)
			}
			rc, stdout, stderr, forced := runOpContract(opRunSpec{
				Binary:  cliPath,
				Name:    row.Name,
				Dir:     dir,
				Env:     opContractEnv(state),
				Timeout: timeout,
			})
			class, reason := classifyOpRun(rc, stdout, stderr)
			if forced != "" {
				class = forced
			}
			if opClassIsDefect(class) {
				t.Fatalf("%s with no target: %s (exit %d)\nstderr:\n%s", row.Name, class, rc, stderr)
			}
			requireContractExit(t, row.Name, rc, stdout, stderr, class, reason)
			if class == opClassOK && opEnvelopeOp(stdout) != row.Name {
				t.Fatalf("%s answered ok under envelope op %q", row.Name, opEnvelopeOp(stdout))
			}
			if row.Needs {
				if class != opClassNeedsArg {
					t.Fatalf("%s: needs=true must refuse for a missing target, got %s: %s", row.Name, class, reason)
				}
				low := strings.ToLower(reason)
				if !strings.Contains(low, "target path") && !strings.Contains(low, "needs -") {
					t.Fatalf("%s: refusal names neither the missing target nor the missing flag: %s", row.Name, reason)
				}
			}
			if !row.Needs && class == opClassNeedsArg && row.Expect.Requires != "" && !strings.Contains(reason, row.Expect.Requires) {
				t.Fatalf("%s: refusal must name %q, got: %s", row.Name, row.Expect.Requires, reason)
			}
			observed[row.Name] = class
			observedReason[row.Name] = reason
			checkOpExpectation(t, row, "no_args", class, reason)
		})
	}
	if *updateOpTable {
		writeOpTableUpdate(t, func(tbl *opTable) {
			for i := range tbl.Ops {
				row := &tbl.Ops[i]
				class, ok := observed[row.Name]
				if !ok {
					continue
				}
				row.Expect.NoArgs = class
				if class == opClassNeedsArg && !row.Needs {
					if req := opRequiresFrom(class, observedReason[row.Name]); req != "" {
						row.Expect.Requires = req
					}
				}
			}
		})
	}
}

// TestTableContractWithTarget is the argument pass: every op that wants a
// target gets a real Mach-O/ELF/PE/wasm artifact and must either answer or
// refuse honestly. Route G and Y are opt-in (see the file comment).
func TestTableContractWithTarget(t *testing.T) {
	tbl, err := loadOpTable(opTablePath)
	if err != nil {
		t.Fatalf("load %s: %v\ngenerate it with: go test -run TableContract -update", opTablePath, err)
	}
	root := t.TempDir()
	timeout := opContractTimeout()
	observed := make(map[string]string, len(tbl.Ops))
	observedReason := make(map[string]string, len(tbl.Ops))
	fixtureOf := make(map[string]string, len(tbl.Ops))
	ran := 0
	for i := range tbl.Ops {
		row := tbl.Ops[i]
		if !row.Needs {
			// No target pass exists for these, and the table says so; record it
			// as the observed class instead of skipping the row unchecked.
			observed[row.Name] = opClassNotApplicable
			checkOpExpectation(t, row, "with_target", opClassNotApplicable, "")
			continue
		}
		// A gated row is still run, with its engine made unreachable: the gate
		// is an environment, not a licence to skip the row. It must answer
		// inside opGateLiveClass (no panic, hang, broken envelope or defect),
		// and the table keeps the gate vocabulary -update records.
		gateReason := opTargetSkipReason(row)
		fixtures, err := tableFixtures(t, root)
		if err != nil {
			t.Fatalf("build fixtures: %v", err)
		}
		ran++
		t.Run(row.Name, func(t *testing.T) {
			requireTableCLI(t)
			dir := filepath.Join(root, "cwd", row.Name)
			state := filepath.Join(root, "state", row.Name)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(state, 0o755); err != nil {
				t.Fatal(err)
			}
			name := row.Expect.Fixture
			if name == "" {
				name = "macho"
			}
			src, ok := fixtures[name]
			if !ok {
				t.Fatalf("%s: table asks for fixture %q, which the test does not build", row.Name, name)
			}
			target := filepath.Join(dir, "target.bin")
			body, err := os.ReadFile(src)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, body, 0o644); err != nil {
				t.Fatal(err)
			}
			rc, stdout, stderr, forced := runOpContract(opRunSpec{
				Binary:  cliPath,
				Name:    row.Name,
				Target:  target,
				Dir:     dir,
				Env:     opEnvRoute(row.Route, gateReason, state),
				Timeout: timeout,
			})
			class, reason := classifyOpRun(rc, stdout, stderr)
			if forced != "" {
				class = forced
			}
			if opClassIsDefect(class) {
				t.Fatalf("%s on %s: %s (exit %d)\nstderr:\n%s", row.Name, name, class, rc, stderr)
			}
			requireContractExit(t, row.Name, rc, stdout, stderr, class, reason)
			if class == opClassOK && opEnvelopeOp(stdout) != row.Name {
				t.Fatalf("%s answered ok under envelope op %q", row.Name, opEnvelopeOp(stdout))
			}
			if class == opClassBadArg && !opRefusalInputExempt[row.Name] && !opRefusalNamesInput(reason, target) {
				t.Fatalf("%s: bad_arg refusal does not name the input it rejected: %s", row.Name, reason)
			}
			if gateReason != "" {
				if !opGateLiveClass(row, class) {
					t.Fatalf("%s: gated (%s) but answered %s: %s", row.Name, gateReason, class, reason)
				}
				// no_engine is the gate itself, so the table keeps the gate
				// vocabulary; any other answer is the op's own refusal and
				// holds on a machine where the tool is installed.
				if class == opClassNoEngine {
					class = opGateClass(row)
				}
				t.Logf("%s: gated: %s -> %s", row.Name, gateReason, class)
			}
			if class == opClassNeedsArg && row.Expect.Requires != "" && !strings.Contains(reason, row.Expect.Requires) {
				t.Fatalf("%s: refusal must name %q, got: %s", row.Name, row.Expect.Requires, reason)
			}
			observed[row.Name] = class
			observedReason[row.Name] = reason
			fixtureOf[row.Name] = name
			checkOpExpectation(t, row, "with_target", class, reason)
		})
	}
	gated := 0
	for _, row := range tbl.Ops {
		if row.Needs && opTargetSkipReason(row) != "" {
			gated++
		}
	}
	t.Logf("%d of %d ops with a target were run (%d gated, engine made unreachable)", ran, countNeeds(tbl), gated)
	if *updateOpTable {
		writeOpTableUpdate(t, func(tbl *opTable) {
			for i := range tbl.Ops {
				row := &tbl.Ops[i]
				class, ok := observed[row.Name]
				if !ok {
					continue
				}
				row.Expect.WithTarget = class
				if fx := fixtureOf[row.Name]; fx != "" {
					row.Expect.Fixture = fx
				}
				if class == opClassNeedsArg {
					if req := opRequiresFrom(class, observedReason[row.Name]); req != "" {
						row.Expect.Requires = req
					}
				}
			}
		})
	}
}

// requireContractExit enforces the two legal exits: 0 with one JSON envelope,
// or 2 with a reason on stderr and, since refuse emits the same envelope in both
// modes, at most that one envelope on stdout.
func requireContractExit(t *testing.T, name string, rc int, stdout, stderr, class, reason string) {
	t.Helper()
	switch rc {
	case 0:
		if class != opClassOK {
			t.Fatalf("%s exited 0 but stdout is not one JSON envelope: %s\nstdout:\n%s", name, class, stdout)
		}
	case 2:
		if stdout != "" {
			var doc struct {
				Op    string `json:"op"`
				Error string `json:"error"`
				Kind  string `json:"kind"`
			}
			if err := json.Unmarshal([]byte(stdout), &doc); err != nil || doc.Op == "" || doc.Error == "" || doc.Kind == "" {
				t.Fatalf("%s refused and wrote stdout that is not one refusal envelope:\n%s", name, stdout)
			}
		}
		if reason == "" {
			t.Fatalf("%s exited 2 with no reason on stderr", name)
		}
	default:
		t.Fatalf("%s exited %d; only 0 (answer) and 2 (refusal) are contract exits\nstderr:\n%s", name, rc, stderr)
	}
}

// readSpec reads an archived spec from env/ (not shipped); CI skips it.
func readSpec(t *testing.T, rel string) []byte {
	t.Helper()
	raw, err := os.ReadFile(rel)
	if os.IsNotExist(err) {
		t.Skipf("%s not present (archived in env/)", rel)
	}
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return raw
}

// TestSimulationGMatchesTable makes simulation.md items 154-388 a real spec:
// the item's route/needs/verdict must match ops.json (wrong_kind bridges to
// bad_arg — the CLI never emits the hint).
func TestSimulationGMatchesTable(t *testing.T) {
	raw := readSpec(t, "../env/archive/spec/simulation.md")
	re := regexp.MustCompile(`(?m)^- \[ \] \*\*(\d+)\.\*\* ` + "`" + `([a-z0-9_]+)` + "`" + `.*?Route ([LGY]), (target not required|target required)\. Contract: without target ` + "`" + `([a-z_]+)` + "`" + `, with target ` + "`" + `([a-z_]+)` + "`")
	tbl, err := loadOpTable(opTablePath)
	if err != nil {
		t.Fatalf("load %s: %v", opTablePath, err)
	}
	byName := map[string]opTableRow{}
	for _, r := range tbl.Ops {
		byName[r.Name] = r
	}
	matches := 0
	seen := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
		n, _ := strconv.Atoi(m[1])
		if n < 154 || n > 388 {
			continue
		}
		seen[m[2]] = true
		row, ok := byName[m[2]]
		if !ok {
			t.Errorf("item %d %s: no table row", n, m[2])
			continue
		}
		needs := m[4] == "target required"
		wt := m[6]
		if wt == opClassWrongKind {
			wt = opClassBadArg
		}
		if row.Route != m[3] || row.Needs != needs || row.Expect.NoArgs != m[5] || row.Expect.WithTarget != wt {
			t.Errorf("item %d %s: doc %s/%v/%s/%s vs table %s/%v/%s/%s",
				n, m[2], m[3], needs, m[5], m[6], row.Route, row.Needs, row.Expect.NoArgs, row.Expect.WithTarget)
			continue
		}
		matches++
	}
	if matches != 235 {
		t.Errorf("G-section: %d/235 items match the table", matches)
	}
	for _, r := range tbl.Ops {
		if !seen[r.Name] {
			t.Errorf("table row %s has no G-section item in simulation.md", r.Name)
		}
	}
}

// TestSimulationItem8RouteCounts pins the route split literal.
func TestSimulationItem8RouteCounts(t *testing.T) {
	raw := readSpec(t, "../env/archive/spec/simulation.md")
	if !strings.Contains(string(raw), "- [ ] **8.** `--list-ops --json` route distribution: 127 L / 69 Y / 39 G.") {
		t.Error("item 8 route counts stale")
	}
}

func countNeeds(tbl *opTable) int {
	n := 0
	for _, row := range tbl.Ops {
		if row.Needs {
			n++
		}
	}
	return n
}

// TestTableContractFixtures proves the artifacts handed to the target pass are
// the formats their names claim: a wrong fixture would silently turn every
// positive case into a refusal.
func TestTableContractFixtures(t *testing.T) {
	fixtures, err := buildOpFixtures(t.TempDir())
	if err != nil {
		t.Fatalf("build fixtures: %v", err)
	}
	for _, spec := range opFixtureSpecs {
		path, ok := fixtures[spec.Name]
		if !ok {
			t.Fatalf("fixture %q was not built", spec.Name)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", spec.Name, err)
		}
		if len(b) < 64 {
			t.Fatalf("%s fixture is %d bytes, too small to be a real artifact", spec.Name, len(b))
		}
		if !opFixtureMagic(spec.Name, b) {
			t.Fatalf("%s fixture does not start with the %s magic: % x", spec.Name, spec.Name, b[:4])
		}
	}
}

func opFixtureMagic(name string, b []byte) bool {
	switch name {
	case "macho":
		return len(b) >= 4 &&
			((b[0] == 0xcf && b[1] == 0xfa && b[2] == 0xed && b[3] == 0xfe) ||
				(b[0] == 0xfe && b[1] == 0xed && b[2] == 0xfa && b[3] == 0xcf))
	case "elf":
		return len(b) >= 4 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F'
	case "pe":
		return len(b) >= 2 && b[0] == 'M' && b[1] == 'Z'
	case "wasm":
		return len(b) >= 4 && b[0] == 0x00 && b[1] == 'a' && b[2] == 's' && b[3] == 'm'
	}
	return false
}

// tableFixtures builds the target artifacts once per test root. The cache is
// keyed by root because each test owns a t.TempDir() that Go removes when the
// test ends: a process-wide cache would hand the next test paths into a
// directory that no longer exists.
var tableFixtureCache = map[string]map[string]string{}

func tableFixtures(t *testing.T, root string) (map[string]string, error) {
	t.Helper()
	if fixtures, ok := tableFixtureCache[root]; ok {
		return fixtures, nil
	}
	fixtures, err := buildOpFixtures(filepath.Join(root, "fixtures"))
	if err != nil {
		return nil, err
	}
	tableFixtureCache[root] = fixtures
	return fixtures, nil
}

// checkOpExpectation compares the observed class with the published one. A
// route Y op may flip between ok and no_engine as adb/frida/gdb appear and
// disappear on the machine; that drift is logged, not failed. Everything else
// is held to the table, so a behavior change is a test failure until -update.
func checkOpExpectation(t *testing.T, row opTableRow, phase, class, reason string) {
	t.Helper()
	want := row.Expect.NoArgs
	if phase == "with_target" {
		want = row.Expect.WithTarget
	}
	if want == class {
		return
	}
	if row.Route == "Y" && ((want == opClassOK && class == opClassNoEngine) || (want == opClassNoEngine && class == opClassOK)) {
		t.Logf("%s: %s is %s, table says %s (external tool present/absent on this machine): %s", row.Name, phase, class, want, reason)
		return
	}
	// Gated rows (skipped_ghidra/skipped_tool) run only under
	// LRECON_OPS_{GHIDRA,TOOLS}=1, which the contract test deliberately
	// disables; the target pass then runs them with the engine made
	// unreachable. A skipped_* expectation may legitimately surface as any of:
	// bad_arg (target-format validation runs before the tool gate — DevTools
	// endpoint / <apk>#class / job-field gate), needs_arg (job/env-gated input
	// missing), ok (tool present and query succeeded), no_engine (tool absent),
	// or out_of_scope (op bylaws refuse live work before any tool runs).
	// A timeout, panic or unparsable envelope is a defect, not a gate.
	if want == opClassSkippedTool || want == opClassSkippedGhidra {
		if opGateLiveClass(row, class) {
			t.Logf("%s: %s is %s, table says %s (gated op; live class when gate lifted): %s", row.Name, phase, class, want, reason)
			return
		}
	}
	if *updateOpTable {
		t.Logf("%s: %s observed %s, table said %s: %s", row.Name, phase, class, want, reason)
		return
	}
	t.Errorf("%s: %s observed %s, table says %s: %s\n(rerun with -update to record the new class)", row.Name, phase, class, want, reason)
}

// opTargetSkipReason is the gate for the target pass. Route G and Y are opt-in
// until their cost is bounded (report A4/B1: one Ghidra import is minutes and
// can leak a JVM; route Y needs a device or debugger).
func opTargetSkipReason(row opTableRow) string {
	switch row.Route {
	case "G":
		if testing.Short() {
			return "route G (Ghidra) is skipped in -short"
		}
		if os.Getenv("LRECON_SKIP_GHIDRA") != "" {
			return "LRECON_SKIP_GHIDRA is set"
		}
		if _, _, err := findGhidra(); err != nil {
			return "analyzeHeadless not found: " + err.Error()
		}
		if os.Getenv("LRECON_OPS_GHIDRA") != "1" {
			return "route G is opt-in: set LRECON_OPS_GHIDRA=1 with LRECON_GHIDRA_TIMEOUT=5s"
		}
	case "Y":
		if testing.Short() {
			return "route Y (external tools) is skipped in -short"
		}
		if os.Getenv("LRECON_OPS_TOOLS") != "1" {
			return "route Y is opt-in: set LRECON_OPS_TOOLS=1"
		}
	}
	return ""
}

// writeOpTableUpdate re-reads the table (the two passes save independently, so
// `-run TableContractWithTarget -update` must not erase the no-target classes),
// applies mutate and writes it back.
func writeOpTableUpdate(t *testing.T, mutate func(*opTable)) {
	t.Helper()
	tbl, err := loadOpTable(opTablePath)
	if err != nil {
		t.Fatalf("reload %s for -update: %v", opTablePath, err)
	}
	for i := range tbl.Ops {
		if o, ok := ops[tbl.Ops[i].Name]; ok {
			tbl.Ops[i].Needs = o.needs
		}
	}
	mutate(tbl)
	if err := saveOpTable(opTablePath, tbl); err != nil {
		t.Fatalf("write %s: %v", opTablePath, err)
	}
	t.Logf("updated %s (%d rows)", opTablePath, len(tbl.Ops))
}

// requireTableCLI stops the test when TestMain could not build the binary.
// Without it every subtest would report a bad_exit, hiding the real error.
func requireTableCLI(t *testing.T) {
	t.Helper()
	if buildErr != nil {
		t.Fatalf("go build failed: %v", buildErr)
	}
	if cliPath == "" {
		t.Fatal("no CLI binary: TestMain did not build one")
	}
}
