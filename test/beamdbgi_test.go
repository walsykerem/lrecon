package main

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"strings"
	"testing"
)

// Fixtures are built from the External Term Format spec rather than captured:
// no erlc is installed here, and a hand-built term can assert the exact shape
// the decoder promises (atom tags, annotation tuple, arity) without shipping a
// blob nobody can read. TestBeamDbgiZlib uses the real compressed-ETF tag that
// OTP writes, so the zlib path is exercised against the format, not a mock.

func etfAtom(s string) []byte { return append([]byte{115, byte(len(s))}, s...) }

func etfSmallInt(n byte) []byte { return []byte{97, n} }

func etfTuple(elems ...[]byte) []byte {
	b := []byte{104, byte(len(elems))}
	for _, e := range elems {
		b = append(b, e...)
	}
	return b
}

func etfList(elems ...[]byte) []byte {
	b := make([]byte, 5)
	b[0] = 108
	binary.BigEndian.PutUint32(b[1:], uint32(len(elems)))
	for _, e := range elems {
		b = append(b, e...)
	}
	return append(b, 106)
}

// etfForm is `{function, Anno, Name, Arity, Clauses}`; anno is the modern
// `{Line,Column}` tuple for foo and the old bare integer for bar.
func etfForm(name string, anno, arity []byte) []byte {
	return etfTuple(etfAtom("function"), anno, etfAtom(name), arity, etfList())
}

func beamDbgiTerm53(forms ...[]byte) []byte {
	return etfTuple(etfAtom("debug_info_v1"), etfAtom("erl_abstract_code"),
		etfTuple(etfList(forms...), etfList()))
}

func zlibTerm(term []byte) []byte {
	var zb bytes.Buffer
	zw := zlib.NewWriter(&zb)
	if _, err := zw.Write(term); err != nil {
		panic(err)
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return zb.Bytes()
}

// beamDbgiCompressed writes the tag-80 shape: compressed ETF whose inflated
// body is the term WITHOUT the 131 version byte, exactly as external.c writes.
func beamDbgiCompressed(term []byte) []byte {
	p := []byte{80}
	p = binary.BigEndian.AppendUint32(p, uint32(len(term)))
	return append(p, zlibTerm(term)...)
}

func beamDbgiSkip(t *testing.T, d Digest, want string) {
	t.Helper()
	for _, s := range d.Skipped {
		if s.Reason == want {
			return
		}
	}
	t.Fatalf("skips %+v missing %q; notes %v", d.Skipped, want, d.Notes)
}

func TestBeamDbgiAbstractForms(t *testing.T) {
	forms := beamDbgiTerm53(
		etfForm("foo", etfTuple(etfSmallInt(3), etfSmallInt(1)), etfSmallInt(1)),
		etfForm("bar", etfSmallInt(7), etfSmallInt(2)),
	)
	blob := beamFile(
		beamAtomsChunk("mymod"),
		beamCinfChunk("8.4.1"),
		beamChunk("Dbgi", beamDbgiCompressed(forms)),
	)
	d, err := Probe(writeTemp(t, "deep.beam", blob))
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind != "beam" || d.Mod != "mymod" {
		t.Fatalf("kind/mod = %q/%q, want beam/mymod", d.Kind, d.Mod)
	}
	for _, want := range []string{"deep: beam-ast mymod:foo/1 @3", "deep: beam-ast mymod:bar/2 @7"} {
		if !containsStr(d.Notes, want) {
			t.Fatalf("notes %v missing %q", d.Notes, want)
		}
	}
	for _, s := range d.Skipped {
		if strings.HasPrefix(s.Reason, "beamdbgi") {
			t.Fatalf("unexpected skip %+v", s)
		}
	}
}

// TestBeamDbgiPlainAbst covers the pre-OTP-20 chunk shape: a plain
// term_to_binary payload that still starts with version byte 131.
func TestBeamDbgiPlainAbst(t *testing.T) {
	term := etfTuple(etfAtom("abstract_v1"), etfList(
		etfForm("old", etfSmallInt(0), etfSmallInt(0))))
	blob := beamFile(
		beamAtomsChunk("m"),
		beamChunk("Abst", append([]byte{131}, term...)),
	)
	d, err := Probe(writeTemp(t, "abst.beam", blob))
	if err != nil {
		t.Fatal(err)
	}
	want := "deep: beam-ast m:old/0"
	if !containsStr(d.Notes, want) {
		t.Fatalf("notes %v missing %q", d.Notes, want)
	}
}

func TestBeamDbgiRefusals(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"absent", nil, "beamdbgi-absent"},
		{"zlib", []byte{80, 0, 0, 0, 4, 0xde, 0xad, 0xbe, 0xef}, "beamdbgi-zlib-failed"},
		{"etf", append([]byte{131, 88}, make([]byte, 8)...), "beamdbgi-etf-unsupported"},
		{"version only", []byte{131}, "beamdbgi-absent"},
		{"no forms", append([]byte{131}, etfTuple(etfAtom("x"))...), "beamdbgi-etf-unsupported"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			blob := beamFile(beamAtomsChunk("m"), beamChunk("Dbgi", c.data))
			d, err := Probe(writeTemp(t, "r.beam", blob))
			if err != nil {
				t.Fatal(err)
			}
			beamDbgiSkip(t, d, c.want)
		})
	}
}

// TestBeamDbgiSilentWhenStripped pins the deliberate silence: a release build
// has no Dbgi/Abst chunk at all, and a skip would misreport that as a failure.
func TestBeamDbgiSilentWhenStripped(t *testing.T) {
	blob := beamFile(beamAtomsChunk("m"))
	d, err := Probe(writeTemp(t, "stripped.beam", blob))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range d.Skipped {
		if strings.HasPrefix(s.Reason, "beamdbgi") {
			t.Fatalf("unexpected skip %+v", s)
		}
	}
}
