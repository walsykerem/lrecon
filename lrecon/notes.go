package main

import "strings"

// deepNote appends a tool-agnostic next-step note to the digest.
//
// The note says WHAT to look at, never WHICH product to run: the same digest
// has to stay useful when the reader's toolchain is not ours. A product name
// must not appear in a note; keep it that way when adding one
// does.
//
// Use it instead of appending a raw string to d.Notes.
func deepNote(d *Digest, msg string) {
	if d == nil {
		return
	}
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return
	}
	d.Notes = append(d.Notes, "deep: "+msg)
}
