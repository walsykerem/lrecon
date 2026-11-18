package main

// Tur 5, go17 lane: gercek davranis simulasyonu.
// Mevcut sim testlerinin kapsamadigi yollari doldurur: badDep premise/konfl,
// stripTarget, refuse stage ve swiftBadTargets. Uretim kodu gevsetilmez.

import (
	"testing"
)

// badDep, dusen bir premise'i isimlendirir. Mevcut testler yalnizca
// premise-aborted ve deps-cycle'i kapsar; premise-unknown ve premise-conflict
// yollari dogrulanmadi. Iki tur de gercek emit uzerinden simule edilir.
func TestTur5Go17EmitPremiseUnknownAndConflict(t *testing.T) {
	w := func(axis string, start int64) Witness {
		return Witness{Axis: axis, Class: axis, Start: start, End: start + 4}
	}
	good := []Witness{w("parser", 0), w("sig", 16)}

	// Deps'teki slot hicbir req'de yok -> premise-unknown.
	d := &Digest{}
	d.emit(
		claimReq{Slot: "producer", Value: "x", Deps: []string{"ghost"}, Witnesses: good},
	)
	if len(d.Claims) != 0 || len(d.Unknown) != 1 {
		t.Fatalf("unknown premise: claims=%+v unknown=%+v", d.Claims, d.Unknown)
	}
	if got := d.Unknown[0].Reasons; len(got) != 1 || got[0] != "premise-unknown:ghost" {
		t.Fatalf("reason = %v, want premise-unknown:ghost", got)
	}

	// Ayni slot iki farkli degerle cakisiyor; dependent bu konflikti adlandirmali.
	d = &Digest{}
	d.emit(
		claimReq{Slot: "language", Value: "Go", Witnesses: good},
		claimReq{Slot: "language", Value: "Rust", Witnesses: good},
		claimReq{Slot: "producer", Value: "x", Deps: []string{"language"}, Witnesses: good},
	)
	if len(d.Conflicts) != 1 || d.Conflicts[0].Slot != "language" {
		t.Fatalf("conflicts = %+v, want one on language", d.Conflicts)
	}
	bySlot := map[string]string{}
	for _, u := range d.Unknown {
		if len(u.Reasons) > 0 {
			bySlot[u.Slot] = u.Reasons[0]
		}
	}
	if bySlot["producer"] != "premise-conflict:language" {
		t.Fatalf("producer reason = %q, want premise-conflict:language", bySlot["producer"])
	}
}

// stripTarget, classify edilmeden once caller'in dosya adini mesajdan cikarir.
// "timeout" adiyla bir dosya timeout sanilmamali; bu gercek bir yanlis
// siniflandirma riskidir ve test edilmemisti.
func TestTur5Go17StripTargetRemovesNameBeforeClassify(t *testing.T) {
	old := refuseState.target
	defer func() { refuseState.target = old }()

	refuseState.target = "/tmp/timeout"
	msg := "/tmp/timeout is not an artifact"
	stripped := stripTarget(msg)
	if stripped != "<target> is not an artifact" {
		t.Fatalf("stripTarget = %q", stripped)
	}
	if got := classify(stripped); got != kindBadArg {
		t.Fatalf("classify(%q) = %s, want bad_arg (not timeout)", stripped, got)
	}

	// Hedef bosken mesaj oldugu gibi kalir.
	refuseState.target = ""
	if got := stripTarget(msg); got != msg {
		t.Fatalf("stripTarget with empty target = %q, want %q", got, msg)
	}
}

// takeRefuseStage okur ve sifirlar: gecikmis bir reddin onceki asamayi
// devralmasi engellenir. Bu davranis test edilmemisti.
func TestTur5Go17RefuseStageIsReadOnce(t *testing.T) {
	defer setRefuseStage("")
	setRefuseStage("decompile")
	if got := takeRefuseStage(); got != "decompile" {
		t.Fatalf("first takeRefuseStage = %q, want decompile", got)
	}
	if got := takeRefuseStage(); got != "" {
		t.Fatalf("second takeRefuseStage = %q, want empty", got)
	}
}

// swiftBadTargets, cozulmus hedeflerin segment disinda kalanlarini sayar.
// Bu fonksiyon icin hic test yoktu; uretimdeki tek cagri yolu boyle
// simule edilir (nulls atlanir, kirik word 0 dondurur).
func TestTur5Go17SwiftBadTargets(t *testing.T) {
	segs := []swiftSeg{{addr: 0x1000, size: 0x100}}
	// base=0x1000, mask=3: 0x10 -> 0x1010 (icarinde), 0x1000 -> 0x2000
	// (disinda), 0 -> null (atlanir).
	s := swiftSec{name: "types", addr: 0x1000, data: le32(0x10, 0x1000, 0)}
	if got := swiftBadTargets(s, 3, segs); got != 1 {
		t.Fatalf("swiftBadTargets = %d, want 1", got)
	}
	// Tum hedefler icerdeyse 0.
	s = swiftSec{name: "types", addr: 0x1000, data: le32(0x10, 0x20)}
	if got := swiftBadTargets(s, 3, segs); got != 0 {
		t.Fatalf("swiftBadTargets all inside = %d, want 0", got)
	}
	// 4'in katinda olmayan veri cozulemez -> 0, panik yok.
	s = swiftSec{name: "types", addr: 0x1000, data: []byte{1, 2, 3}}
	if got := swiftBadTargets(s, 3, segs); got != 0 {
		t.Fatalf("swiftBadTargets cut word = %d, want 0", got)
	}
}

// ops.json yayinlanmis sozlesme; bu lane'in op satirlari route/needs/class
// bakimindan kaymamali. Walsyrea sim yonlendirmesi dogrudan bu tablodan okunur.
func TestTur5Go17OpTableRouteContract(t *testing.T) {
	tbl, err := loadOpTable("testdata/ops.json")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]opTableRow{
		"close_rizin_debug_session":  {Name: "close_rizin_debug_session", Route: "Y", Needs: true, Expect: opExpectation{NoArgs: "needs_arg", WithTarget: "out_of_scope", Fixture: "macho"}},
		"get_call_graph":             {Name: "get_call_graph", Route: "G", Needs: true, Expect: opExpectation{NoArgs: "needs_arg", WithTarget: "skipped_ghidra", Fixture: "macho"}},
		"inspect_macho":              {Name: "inspect_macho", Route: "L", Needs: true, Expect: opExpectation{NoArgs: "needs_arg", WithTarget: "ok", Fixture: "macho"}},
		"inspect_web_page":           {Name: "inspect_web_page", Route: "Y", Needs: true, Expect: opExpectation{NoArgs: "needs_arg", WithTarget: "bad_arg", Fixture: "macho"}},
		"list_strings":               {Name: "list_strings", Route: "L", Needs: true, Expect: opExpectation{NoArgs: "needs_arg", WithTarget: "ok", Fixture: "macho"}},
		"open_binary":                {Name: "open_binary", Route: "L", Needs: true, Expect: opExpectation{NoArgs: "needs_arg", WithTarget: "ok", Fixture: "macho"}},
		"read_function_instructions": {Name: "read_function_instructions", Route: "G", Needs: true, Expect: opExpectation{NoArgs: "needs_arg", WithTarget: "needs_arg", Fixture: "macho", Requires: "LRECON_AT"}},
		"search_strings":             {Name: "search_strings", Route: "L", Needs: true, Expect: opExpectation{NoArgs: "needs_arg", WithTarget: "needs_arg", Fixture: "macho", Requires: "LRECON_QUERY"}},
		"trace_web_module_imports":   {Name: "trace_web_module_imports", Route: "L", Needs: true, Expect: opExpectation{NoArgs: "needs_arg", WithTarget: "ok", Fixture: "macho"}},
	}
	seen := map[string]bool{}
	for _, row := range tbl.Ops {
		w, ok := want[row.Name]
		if !ok {
			continue
		}
		seen[row.Name] = true
		if row.Route != w.Route || row.Needs != w.Needs {
			t.Errorf("%s: route/needs = %q/%v, want %q/%v", row.Name, row.Route, row.Needs, w.Route, w.Needs)
		}
		if row.Expect.NoArgs != w.Expect.NoArgs || row.Expect.WithTarget != w.Expect.WithTarget {
			t.Errorf("%s: class = %q/%q, want %q/%q", row.Name, row.Expect.NoArgs, row.Expect.WithTarget, w.Expect.NoArgs, w.Expect.WithTarget)
		}
		if row.Expect.Requires != w.Expect.Requires {
			t.Errorf("%s: requires = %q, want %q", row.Name, row.Expect.Requires, w.Expect.Requires)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("ops.json missing row %q", name)
		}
	}
}
