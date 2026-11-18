package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestTextExportsZeroVisible: a zero export count is a decision input, so it
// prints instead of being omitted; the marker says whether a table was read.
func TestTextExportsZeroVisible(t *testing.T) {
	d := Digest{Kind: "macho", Exports: 0, Symbols: symStripped}
	text := d.Text()
	for _, want := range []string{"exports: 0\n", "symbols: stripped\n"} {
		if !strings.Contains(text, want) {
			t.Fatalf("Text() missing %q:\n%s", want, text)
		}
	}
	// Nothing read at all is not the same answer as a read, empty count.
	if got := (Digest{Kind: "macho"}).Text(); strings.Contains(got, "exports") || strings.Contains(got, "symbols") {
		t.Fatalf("Text() claims an export answer nobody measured:\n%s", got)
	}
}

// TestDigestSymbolsJSON: the marker must reach machine consumers too.
func TestDigestSymbolsJSON(t *testing.T) {
	d := Digest{Kind: "macho", Exports: 0, Symbols: symStripped}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"symbols":"stripped"`) {
		t.Fatalf("JSON lost the symbols marker: %s", b)
	}
	// A read, empty count is exports 0: omitempty drops the zero, so the marker is
	// what makes the number recoverable in JSON and in text alike.
	if !strings.Contains(d.Text(), "exports: 0\n") || !strings.Contains(string(b), `"symbols"`) {
		t.Fatalf("zero exports not recoverable: json %s text %q", b, d.Text())
	}
}
