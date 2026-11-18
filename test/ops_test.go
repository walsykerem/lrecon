package main

import (
	"sort"
	"strings"
	"testing"
)

// The registry is the only place the inventory items are addressed by name,
// so its contract is small and worth pinning: unique names, a route, a
// description, and an error rather than a panic for an unknown item.
func TestOpsRegistry(t *testing.T) {
	names := opNames()
	// The pin follows testdata/ops.json, not a hand-kept count: the 229 rea
	// items are the floor, and addendum items (adb 451-475) grow the table.
	// A dropped item would otherwise still leave the registry green.
	tbl, err := loadOpTable(opTablePath)
	if err != nil {
		t.Fatalf("load %s: %v", opTablePath, err)
	}
	if len(names) != len(tbl.Ops) {
		t.Fatalf("%d ops registered, %s lists %d", len(names), opTablePath, len(tbl.Ops))
	}
	if len(names) < 229 {
		t.Fatalf("%d ops registered, the rea inventory floor is 229", len(names))
	}
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			t.Fatalf("duplicate op name %q", name)
		}
		seen[name] = true
		o := ops[name]
		if o.name != name {
			t.Fatalf("op registered under %q carries name %q", name, o.name)
		}
		if strings.TrimSpace(o.desc) == "" {
			t.Fatalf("op %q has an empty description", name)
		}
		switch o.route {
		case "L", "G", "Y":
		default:
			t.Fatalf("op %q has route %q", name, o.route)
		}
	}
	if !sort.StringsAreSorted(names) {
		t.Fatal("opNames is not sorted")
	}
}

func TestOpsUnknownAndMissingTarget(t *testing.T) {
	if _, err := runOp("no_such_op", ""); err == nil {
		t.Fatal("unknown op returned no error")
	} else if !strings.Contains(err.Error(), "unknown op") {
		t.Fatalf("unknown op error does not name the problem: %v", err)
	}
	// Any item that declares needs:true must refuse an empty target instead of
	// reading a file named "".
	checked := 0
	for _, name := range opNames() {
		if !ops[name].needs {
			continue
		}
		checked++
		if _, err := runOp(name, ""); err == nil {
			t.Fatalf("op %q accepted an empty target", name)
		} else if !strings.Contains(err.Error(), "needs a target") {
			t.Fatalf("op %q refused an empty target without saying why: %v", name, err)
		}
	}
	// The published contract (testdata/ops.json) carries the same flag, so the
	// pin follows the table instead of a hand-kept number: an out-of-scope op
	// that stops needing a target must move both together.
	tbl, err := loadOpTable(opTablePath)
	if err != nil {
		t.Fatalf("load %s: %v", opTablePath, err)
	}
	want := 0
	for _, row := range tbl.Ops {
		if row.Needs {
			want++
		}
	}
	if checked != want {
		t.Fatalf("%d ops declare needs, %s says %d", checked, opTablePath, want)
	}
}

// skip is a refusal with a reason; an empty reason would read as success.
func TestSkipCarriesReason(t *testing.T) {
	s := skipf("tool %s not installed", "jadx")
	if s.Reason == "" || !strings.Contains(s.Reason, "jadx") {
		t.Fatalf("skip lost its reason: %q", s.Reason)
	}
}
