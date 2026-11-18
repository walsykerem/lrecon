package main

import (
	"reflect"
	"testing"
)

// TestDeepNote drives the real branches: nil digest, empty/whitespace message,
// and a normal message (whose surrounding space must be trimmed and prefixed).
func TestDeepNote(t *testing.T) {
	deepNote(nil, "keep going") // must not panic

	d := &Digest{}
	deepNote(d, "   ")
	if len(d.Notes) != 0 {
		t.Fatalf("whitespace note appended: %q", d.Notes)
	}

	deepNote(d, "  look at the import table  ")
	if !reflect.DeepEqual(d.Notes, []string{"deep: look at the import table"}) {
		t.Fatalf("notes = %q", d.Notes)
	}

	deepNote(d, "second step")
	if !reflect.DeepEqual(d.Notes, []string{
		"deep: look at the import table",
		"deep: second step",
	}) {
		t.Fatalf("notes after append = %q", d.Notes)
	}
}
