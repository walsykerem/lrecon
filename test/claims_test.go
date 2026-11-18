package main

import (
	"strconv"
	"testing"
)

func wt(mech string, off, ln int64) Witness {
	return Witness{Axis: mech, Class: mech, Value: mech + "@" + strconv.FormatInt(off, 10), Start: off, End: off + ln}
}

// TestLanguageNeeds2Witness: one witness is a hint. The slot has to say so
// instead of turning a single reader into a language claim.
func TestLanguageNeeds2Witness(t *testing.T) {
	d := &Digest{}
	d.emit(claimReq{Slot: "language", Value: "go", Witnesses: []Witness{wt("parser", 0, 4)}})
	if len(d.Claims) != 0 {
		t.Fatalf("one witness produced %d claims: %+v", len(d.Claims), d.Claims)
	}
	if len(d.Unknown) != 1 {
		t.Fatalf("Unknown = %+v, want one entry", d.Unknown)
	}
	u := d.Unknown[0]
	if u.Slot != "language" || len(u.Reasons) != 1 || u.Reasons[0] != "witness-count" {
		t.Fatalf("Unknown = %+v, want language refused for witness-count", u)
	}
	if u.Witness == nil || u.Witness.Start != 0 {
		t.Fatalf("Witness = %+v, want the byte the reader looked at", u.Witness)
	}
	if len(u.Searched) != 1 || u.Searched[0] != "parser" {
		t.Fatalf("Searched = %q, want the source that was read", u.Searched)
	}

	// Same proposal with a second mechanism on a disjoint range is a claim.
	d = &Digest{}
	d.emit(claimReq{Slot: "language", Value: "go", Witnesses: []Witness{wt("parser", 0, 4), wt("sig", 8, 4)}})
	if len(d.Claims) != 1 || d.Claims[0].Slot != "language" || d.Claims[0].Value != "go" {
		t.Fatalf("Claims = %+v, want one language=go claim", d.Claims)
	}
	if len(d.Unknown) != 0 {
		t.Fatalf("Unknown = %+v, want none", d.Unknown)
	}
	if want := 2.0 / 3.0; d.Claims[0].Conf != want {
		t.Fatalf("Conf = %v, want %v", d.Claims[0].Conf, want)
	}
	// The one-release JSON contract still carries a single source and offset.
	if d.Claims[0].Source != "parser" || d.Claims[0].ByteOffset != 0 {
		t.Fatalf("Claim = %+v, want source and byte_offset kept", d.Claims[0])
	}
}

// TestEmitRefusesOverlap: two mechanisms reading the same bytes are one read,
// however they are tagged.
func TestEmitRefusesOverlap(t *testing.T) {
	d := &Digest{}
	d.emit(claimReq{Slot: "producer", Value: "electron", Witnesses: []Witness{wt("parser", 0, 100), wt("sig", 50, 100)}})
	if len(d.Claims) != 0 {
		t.Fatalf("overlapping witnesses produced a claim: %+v", d.Claims)
	}
	if len(d.Unknown) != 1 || d.Unknown[0].Reasons[0] != "witness-overlap" {
		t.Fatalf("Unknown = %+v, want witness-overlap", d.Unknown)
	}
	if gap := witnessGap([]Witness{wt("parser", 0, 100), wt("sig", 100, 100)}); gap != "" {
		t.Fatalf("adjacent ranges are disjoint and must count as two reads, got %q", gap)
	}
	if gap := witnessGap([]Witness{wt("parser", 0, 100), wt("sig", 99, 100)}); gap != "witness-overlap" {
		t.Fatalf("a one-byte overlap is an overlap, got %q", gap)
	}
}

// TestEmitRefusesSameMech: the same reader counted twice is not independence.
func TestEmitRefusesSameMech(t *testing.T) {
	d := &Digest{}
	d.emit(claimReq{Slot: "language", Value: "rust", Witnesses: []Witness{wt("parser", 0, 10), wt("parser", 20, 10)}})
	if len(d.Claims) != 0 {
		t.Fatalf("same mechanism produced a claim: %+v", d.Claims)
	}
	if len(d.Unknown) != 1 || d.Unknown[0].Reasons[0] != "witness-same-mech" {
		t.Fatalf("Unknown = %+v, want witness-same-mech", d.Unknown)
	}

	// A mechanism outside the closed set has no identity to compare against.
	d = &Digest{}
	d.emit(claimReq{Slot: "language", Value: "rust", Witnesses: []Witness{wt("guess", 0, 10), wt("sig", 20, 10)}})
	if len(d.Unknown) != 1 || d.Unknown[0].Reasons[0] != "witness-mech-unknown" {
		t.Fatalf("Unknown = %+v, want witness-mech-unknown", d.Unknown)
	}
}

// TestConflictKeepsBoth: two values for one slot are reported as a conflict. No
// value is picked, and the slot does not appear as a claim.
func TestConflictKeepsBoth(t *testing.T) {
	d := &Digest{}
	d.emit(
		claimReq{Slot: "language", Value: "go", Witnesses: []Witness{wt("parser", 0, 10), wt("sig", 20, 10)}},
		claimReq{Slot: "language", Value: "rust", Witnesses: []Witness{wt("parser", 40, 10), wt("passthrough", 60, 10)}},
	)
	if len(d.Claims) != 0 {
		t.Fatalf("conflicted slot produced claims: %+v", d.Claims)
	}
	if len(d.Conflicts) != 1 {
		t.Fatalf("Conflicts = %+v, want one entry", d.Conflicts)
	}
	c := d.Conflicts[0]
	if c.Slot != "language" {
		t.Fatalf("conflict slot = %q, want language", c.Slot)
	}
	if len(c.Values) != 2 || c.Values[0] != "go" || c.Values[1] != "rust" {
		t.Fatalf("Values = %q, want both go and rust", c.Values)
	}
	if len(c.Witnesses) != 4 {
		t.Fatalf("Witnesses = %d, want both sides' four witnesses", len(c.Witnesses))
	}
}

// TestPremiseAborts: a claim resting on a dropped claim is dropped with it, and
// the reason names the premise. A premise that stands carries its dependent.
func TestPremiseAborts(t *testing.T) {
	d := &Digest{}
	d.emit(
		claimReq{Slot: "language", Value: "js", Witnesses: []Witness{wt("parser", 0, 10)}},
		claimReq{Slot: "producer", Value: "electron", Deps: []string{"language"}, Witnesses: []Witness{wt("parser", 20, 10), wt("sig", 40, 10)}},
	)
	if len(d.Claims) != 0 {
		t.Fatalf("Claims = %+v, want none", d.Claims)
	}
	if len(d.Unknown) != 2 {
		t.Fatalf("Unknown = %+v, want two entries", d.Unknown)
	}
	reasons := map[string]string{}
	for _, u := range d.Unknown {
		reasons[u.Slot] = u.Reasons[0]
	}
	if reasons["language"] != "witness-count" {
		t.Fatalf("language reason = %q, want witness-count", reasons["language"])
	}
	if reasons["producer"] != "premise-aborted:language" {
		t.Fatalf("producer reason = %q, want premise-aborted:language", reasons["producer"])
	}

	d = &Digest{}
	d.emit(
		claimReq{Slot: "language", Value: "js", Witnesses: []Witness{wt("parser", 0, 10), wt("sig", 15, 10)}},
		claimReq{Slot: "producer", Value: "electron", Deps: []string{"language"}, Witnesses: []Witness{wt("parser", 20, 10), wt("sig", 40, 10)}},
	)
	if len(d.Claims) != 2 {
		t.Fatalf("Claims = %+v, want language and producer", d.Claims)
	}
	if len(d.Unknown) != 0 {
		t.Fatalf("Unknown = %+v, want none", d.Unknown)
	}
}

// TestEmitRefusesDepsCycle: two claims resting on each other settle on nothing,
// so both are refused instead of one being picked by batch order.
func TestEmitRefusesDepsCycle(t *testing.T) {
	d := &Digest{}
	d.emit(
		claimReq{Slot: "language", Value: "go", Deps: []string{"producer"}, Witnesses: []Witness{wt("parser", 0, 10), wt("sig", 15, 10)}},
		claimReq{Slot: "producer", Value: "gomono", Deps: []string{"language"}, Witnesses: []Witness{wt("parser", 20, 10), wt("sig", 40, 10)}},
	)
	if len(d.Claims) != 0 {
		t.Fatalf("Claims = %+v, want none", d.Claims)
	}
	if len(d.Unknown) != 2 {
		t.Fatalf("Unknown = %+v, want two entries", d.Unknown)
	}
	for _, u := range d.Unknown {
		if len(u.Reasons) != 1 || u.Reasons[0] != "deps-cycle" {
			t.Fatalf("%s reason = %q, want deps-cycle", u.Slot, u.Reasons)
		}
	}
}

// TestSlotUnsupported: the claim surface is two slots. Anything else is refused
// by name rather than silently generalised.
func TestSlotUnsupported(t *testing.T) {
	d := &Digest{}
	d.emit(claimReq{Slot: "kind", Value: "macho", Witnesses: []Witness{wt("parser", 0, 10), wt("sig", 20, 10)}})
	if len(d.Claims) != 0 {
		t.Fatalf("unsupported slot produced a claim: %+v", d.Claims)
	}
	if len(d.Unknown) != 1 || d.Unknown[0].Slot != "kind" {
		t.Fatalf("Unknown = %+v, want kind", d.Unknown)
	}
	if d.Unknown[0].Reasons[0] != "slot-unsupported" {
		t.Fatalf("reason = %q, want slot-unsupported", d.Unknown[0].Reasons[0])
	}
	if !claimSlots["language"] || !claimSlots["producer"] || len(claimSlots) != 2 {
		t.Fatalf("claimSlots = %v, want exactly language and producer", claimSlots)
	}
}
