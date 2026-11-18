package main

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// Synthetic buffers only: a .beam is an IFF wrapper around length-prefixed
// chunks, so these builders are the mirror of the walk in beam.go.

func beamChunk(id string, data []byte) []byte {
	b := make([]byte, 8+len(data))
	copy(b, id)
	binary.BigEndian.PutUint32(b[4:8], uint32(len(data)))
	copy(b[8:], data)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func beamAtomsChunk(names ...string) []byte {
	d := make([]byte, 4)
	binary.BigEndian.PutUint32(d, uint32(len(names)))
	for _, n := range names {
		d = append(d, byte(len(n)))
		d = append(d, n...)
	}
	return beamChunk("AtU8", d)
}

func beamCinfChunk(s string) []byte {
	return beamChunk("CInf", append([]byte{byte(len(s))}, s...))
}

func beamFile(chunks ...[]byte) []byte {
	body := []byte("BEAM")
	for _, c := range chunks {
		body = append(body, c...)
	}
	b := make([]byte, 8)
	copy(b, "FOR1")
	binary.BigEndian.PutUint32(b[4:8], uint32(len(body)))
	return append(b, body...)
}

func TestBeamMatch(t *testing.T) {
	good := beamFile(beamAtomsChunk("mymod"))
	cases := []struct {
		name string
		head []byte
		size int64
		want bool
	}{
		{"nil", nil, 0, false},
		{"short", good[:11], 11, false},
		{"for1 without beam", append([]byte("FOR1"), make([]byte, 8)...), 12, false},
		{"beam payload", good, int64(len(good)), true},
		{"no wrapper", append([]byte("XXXX"), good[4:]...), int64(len(good)), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := beamMatch(c.head, c.size); got != c.want {
				t.Fatalf("beamMatch = %v, want %v", got, c.want)
			}
		})
	}
}

func TestBeamValid(t *testing.T) {
	b := beamFile(
		beamAtomsChunk("mymod", "foo", "bar"),
		beamCinfChunk("8.5.3"),
		beamChunk("Code", []byte{1, 2, 3, 4}),
	)
	d, err := Probe(writeTemp(t, "mymod.beam", b))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "beam" || d.Format != "beam" {
		t.Fatalf("kind/format = %q/%q, want beam/beam", d.Kind, d.Format)
	}
	if d.Mod != "mymod" {
		t.Fatalf("mod = %q, want mymod", d.Mod)
	}
	if got := strings.Join(d.Imports, ","); got != "foo,bar" {
		t.Fatalf("imports = %q, want foo,bar", got)
	}
	if d.Toolchain != "erlang 8.5.3" {
		t.Fatalf("toolchain = %q, want erlang 8.5.3", d.Toolchain)
	}
	if len(d.Skipped) != 0 {
		t.Fatalf("skipped = %+v, want none", d.Skipped)
	}
	if d.Coverage == nil || d.Coverage.Parsed != 2 || d.Coverage.Unknown != 1 {
		t.Fatalf("coverage = %+v, want parsed 2 unknown 1", d.Coverage)
	}
	if note := strings.Join(d.Notes, "; "); strings.Contains(note, "FOR1 size") {
		t.Fatalf("notes = %q, want no size complaint on a well-formed wrapper", note)
	}
}

func TestBeamNameCap(t *testing.T) {
	names := make([]string, 0, beamMaxNames+44)
	for i := range beamMaxNames + 44 {
		names = append(names, fmt.Sprintf("n%d", i))
	}
	d, err := Probe(writeTemp(t, "capped.beam", beamFile(beamAtomsChunk(names...))))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Mod != "n0" {
		t.Fatalf("mod = %q, want n0", d.Mod)
	}
	if len(d.Imports) != beamMaxNames-1 {
		t.Fatalf("imports = %d, want %d", len(d.Imports), beamMaxNames-1)
	}
	if len(d.Skipped) != 1 || d.Skipped[0].Reason != "beam-name-cap" {
		t.Fatalf("skipped = %+v, want one beam-name-cap", d.Skipped)
	}
}

func TestBeamTruncatedChunk(t *testing.T) {
	t.Run("chunk size overruns file", func(t *testing.T) {
		b := beamFile(beamAtomsChunk("mymod", "foo"))
		b = append(b, []byte("Code")...)
		b = append(b, 0, 0, 0x10, 0) // claims 4096 bytes
		b = append(b, 1, 2, 3, 4)
		d, err := Probe(writeTemp(t, "truncated.beam", b))
		if err != nil {
			t.Fatalf("Probe: %v", err)
		}
		if d.Mod != "mymod" {
			t.Fatalf("mod = %q, want the names before the break", d.Mod)
		}
		if len(d.Skipped) == 0 || d.Skipped[len(d.Skipped)-1].Reason != "beam-truncated" {
			t.Fatalf("skipped = %+v, want beam-truncated", d.Skipped)
		}
	})
	t.Run("atom table count lies", func(t *testing.T) {
		data := make([]byte, 4)
		binary.BigEndian.PutUint32(data, 5)
		data = append(data, 3, 'f', 'o', 'o')
		d, err := Probe(writeTemp(t, "count.beam", beamFile(beamChunk("AtU8", data))))
		if err != nil {
			t.Fatalf("Probe: %v", err)
		}
		if len(d.Skipped) != 1 || d.Skipped[0].Reason != "beam-truncated" {
			t.Fatalf("skipped = %+v, want one beam-truncated", d.Skipped)
		}
	})
}

func TestBeamNoFor1(t *testing.T) {
	b := beamFile(beamAtomsChunk("mymod", "foo"))
	copy(b[:4], "XXXX")
	d, err := Probe(writeTemp(t, "nowrapper.beam", b))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "beam" {
		t.Fatalf("kind = %q, want beam", d.Kind)
	}
	if d.Mod != "" {
		t.Fatalf("mod = %q, want nothing without the wrapper", d.Mod)
	}
	if len(d.Skipped) != 1 || d.Skipped[0].Reason != "no-iff-wrapper" {
		t.Fatalf("skipped = %+v, want one no-iff-wrapper", d.Skipped)
	}
}

func TestBeamLyingSize(t *testing.T) {
	b := beamFile(beamAtomsChunk("mymod", "foo"), beamCinfChunk("8.5.3"))
	binary.BigEndian.PutUint32(b[4:8], 4) // neither filesize-8 nor a chunk bound
	d, err := Probe(writeTemp(t, "liar.beam", b))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Mod != "mymod" || d.Toolchain != "erlang 8.5.3" {
		t.Fatalf("mod/toolchain = %q/%q, want names and version despite the size", d.Mod, d.Toolchain)
	}
	if len(d.Skipped) != 0 {
		t.Fatalf("skipped = %+v, want none", d.Skipped)
	}
	if note := strings.Join(d.Notes, "; "); !strings.Contains(note, "FOR1 size 4") {
		t.Fatalf("notes = %q, want the size mismatch", note)
	}
}
