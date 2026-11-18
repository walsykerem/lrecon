package main

import (
	"strings"
	"testing"
)

// A cut digest must say it was cut: a truncated answer read as complete is wrong,
// not just small. Every case below asserts the note, not only the byte count.
func TestTruncate(t *testing.T) {
	const s = "kind: macho\nformat: fat\nmod: github.com/cli/cli/v2\n"
	const note = "note: truncated at "
	cases := []struct {
		name  string
		in    string
		limit int
		want  string // expected body before the note
	}{
		{"under limit unchanged", s, 4096, s},
		{"exact boundary unchanged", s, len(s), s},
		{"over limit cuts at last newline", s, 14, "kind: macho\n"},
		{"both lines fit cut", "aa\nbb\ncc\n", 7, "aa\nbb\n"},
		{"no newline fits", "abcdefgh", 3, "ab\n"},
		{"zero limit unchanged", s, 0, s},
		{"negative limit unchanged", s, -5, s},
		{"empty string", "", 10, ""},
		{"newline at first byte", "\nabcdef", 3, "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := truncate(tc.in, tc.limit)
			if tc.limit <= 0 || len(tc.in) <= tc.limit {
				if got != tc.want {
					t.Fatalf("truncate(%q, %d) = %q, want %q", tc.in, tc.limit, got, tc.want)
				}
				if strings.Contains(got, note) {
					t.Fatalf("untruncated output carries a truncation note: %q", got)
				}
				return
			}
			body, hasNote := got, false
			if before, _, ok := strings.Cut(got, note); ok {
				body, hasNote = before, true
			}
			if !hasNote {
				t.Fatalf("truncate(%q, %d) cut without a note: %q", tc.in, tc.limit, got)
			}
			if body != tc.want {
				t.Fatalf("body = %q, want %q", body, tc.want)
			}
			if !strings.HasSuffix(body, "\n") && body != "" {
				t.Fatalf("cut mid-line: %q", body)
			}
			if !strings.Contains(got, "--max-bytes") {
				t.Fatalf("note does not name the escape hatch: %q", got)
			}
		})
	}
}

// The old gap: a digest cut by the default budget looked complete.
func TestTruncateNoteOnCLIOutput(t *testing.T) {
	out, code := runCLI(t, "--max-bytes", "40", cliPath)
	if code != 0 {
		t.Fatalf("exit %d, want 0", code)
	}
	if !strings.Contains(out, "note: truncated at ") {
		t.Fatalf("no truncation note in %q", out)
	}
}
