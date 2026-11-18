package main

import "testing"

const (
	fixtureMagic = 0x7f
	fixtureOffA  = int64(16)
	fixtureOffB  = int64(48)
)

func fixtureBytes() []byte {
	b := make([]byte, 64)
	b[fixtureOffA] = fixtureMagic
	b[fixtureOffB] = fixtureMagic
	return b
}

// deriveWitnesses mirrors a reader: two call sites, one class each, and a witness
// only when the byte the witness names is really the magic it claims.
func deriveWitnesses(b []byte) *Digest {
	d := &Digest{FileSize: int64(len(b))}
	if b[fixtureOffA] == fixtureMagic {
		d.witness(Witness{Axis: "magic", Class: "A", Value: "fixture", Start: fixtureOffA, End: fixtureOffA + 1})
	}
	if b[fixtureOffB] == fixtureMagic {
		d.witness(Witness{Axis: "magic", Class: "B", Value: "fixture", Start: fixtureOffB, End: fixtureOffB + 1})
	}
	return d
}

func witnessClassesOf(d *Digest) map[string]bool {
	out := map[string]bool{}
	for _, w := range d.witnesses {
		out[w.Class] = true
	}
	return out
}

// TestWitnessMutationSurvival is the load-bearing one: flip one byte and exactly
// the class that read that byte must die. A witness that survives its own byte
// being destroyed was never derived from the file.
func TestWitnessMutationSurvival(t *testing.T) {
	if c := witnessClassesOf(deriveWitnesses(fixtureBytes())); !c["A"] || !c["B"] {
		t.Fatalf("baseline lost a class: %v", c)
	}

	aFlipped := fixtureBytes()
	aFlipped[fixtureOffA] = 0
	got := deriveWitnesses(aFlipped)
	if witnessClassesOf(got)["A"] {
		t.Fatal("A flip survived: class A still present")
	}
	if !witnessClassesOf(got)["B"] {
		t.Fatalf("A flip also dropped class B: %v", witnessClassesOf(got))
	}
	if got.witnessed("fixture") {
		t.Fatal("single class counted as witness")
	}

	bFlipped := fixtureBytes()
	bFlipped[fixtureOffB] = 0
	got = deriveWitnesses(bFlipped)
	if witnessClassesOf(got)["B"] {
		t.Fatal("B flip survived: class B still present")
	}
	if !witnessClassesOf(got)["A"] {
		t.Fatalf("B flip also dropped class A: %v", witnessClassesOf(got))
	}

	if !deriveWitnesses(fixtureBytes()).witnessed("fixture") {
		t.Fatal("two disjoint classes not counted as witness")
	}
}

// TestWitnessNeedsTwoClasses pins the freeze: one class twice is one witness, an
// overlap is one witness, and one call site cannot claim two classes.
func TestWitnessNeedsTwoClasses(t *testing.T) {
	var d Digest
	d.witness(Witness{Axis: "note", Class: "note", Value: "build-id", Start: 8, End: 20})
	d.witness(Witness{Axis: "note", Class: "note", Value: "build-id", Start: 40, End: 52})
	if d.witnessed("build-id") {
		t.Fatal("same class counted as witness twice")
	}

	var overlap Digest
	overlap.witness(Witness{Axis: "note", Class: "note", Value: "v", Start: 0, End: 10})
	overlap.witness(Witness{Axis: "slice", Class: "slice", Value: "v", Start: 5, End: 15})
	if overlap.witnessed("v") {
		t.Fatal("overlapping spans counted as independent witnesses")
	}

	defer func() {
		if recover() == nil {
			t.Fatal("second class from same call site did not panic")
		}
	}()
	twoClassesOneSite(&d)
}

// twoClassesOneSite is deliberately one call site: the class is frozen by site,
// so the caller cannot rename its way to a second witness.
func twoClassesOneSite(d *Digest) {
	for _, class := range []string{"note", "slice"} {
		d.witness(Witness{Axis: "dup", Class: class, Value: "dup", Start: 0, End: 1})
	}
}

// TestBytesScannedIsUnion: bytes_scanned is the union of recorded spans, not a
// counter, so a second walk over the same note does not inflate coverage.
func TestBytesScannedIsUnion(t *testing.T) {
	var d Digest
	d.witness(Witness{Axis: "note", Class: "note", Value: "build-id", Start: 100, End: 200})
	d.witness(Witness{Axis: "section", Class: "section", Value: "build-id", Start: 150, End: 250})
	if d.BytesScanned != 150 {
		t.Fatalf("bytes_scanned = %d, want union 150", d.BytesScanned)
	}

	var adjacent Digest
	adjacent.witness(Witness{Axis: "note", Class: "note", Value: "v", Start: 0, End: 8})
	adjacent.witness(Witness{Axis: "slice", Class: "slice", Value: "v", Start: 8, End: 16})
	if adjacent.BytesScanned != 16 {
		t.Fatalf("bytes_scanned = %d, want 16", adjacent.BytesScanned)
	}

	adjacent.scanned(64) // read cursor was at 0, so this read overlaps [0,16)
	if adjacent.BytesScanned != 64 {
		t.Fatalf("bytes_scanned = %d, want 64 (re-read counted once)", adjacent.BytesScanned)
	}

	var seq Digest
	seq.scanned(64)
	seq.scanned(16)
	if seq.BytesScanned != 80 {
		t.Fatalf("bytes_scanned = %d, want sequential 80", seq.BytesScanned)
	}
}

// BenchmarkWitnessAtSequential measures the per-witness bookkeeping: every
// witness recomputes BytesScanned, and a reader that scans a file emits one per
// span. Sequential spans are the common shape, so the union is already sorted.
func BenchmarkWitnessAtSequential(b *testing.B) {
	for b.Loop() {
		var d Digest
		for j := range 200 {
			d.witness(Witness{Axis: "read", Class: "read", Value: "read", Start: int64(j * 64), End: int64(j*64 + 64)})
		}
	}
}

// BenchmarkMergeSpansSorted keeps the union path alone: 200 spans, already in
// order and disjoint.
func BenchmarkMergeSpansSorted(b *testing.B) {
	spans := make([][2]int64, 200)
	for i := range spans {
		spans[i] = [2]int64{int64(i * 64), int64(i*64 + 64)}
	}
	b.ResetTimer()
	for b.Loop() {
		mergeSpans(spans)
	}
}
