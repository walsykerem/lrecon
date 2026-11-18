package main

import (
	"flag"
	"strings"
	"testing"
)

// conflictFlags mirrors the flags cliConflict reads. A full FlagSet is main()'s
// business; the conflict check only needs the names to be present.
func conflictFlags() *flag.FlagSet {
	fs := flag.NewFlagSet("lrecon", flag.ContinueOnError)
	for _, name := range []string{"op", "ext-op", "diff", "explain", "deep", "extract", "extract-all"} {
		fs.String(name, "", "")
	}
	fs.Int("pid", 0, "")
	return fs
}

// A repeated single-value flag keeps only its last value, so the first answer a
// caller asked for never runs. Every job flag counts, not just --op.
func TestRepeatFlag(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"ext-op twice", []string{"--ext-op", "a", "--ext-op", "b", "/bin/ls"}, "--ext-op given 2 times: one call answers one question"},
		{"diff twice", []string{"--diff", "a", "--diff", "b", "/bin/ls"}, "--diff given 2 times: one call answers one question"},
		{"explain twice", []string{"--explain", "a", "--explain", "b"}, "--explain given 2 times: one call answers one question"},
		{"deep twice", []string{"--deep", "a", "--deep", "b"}, "--deep given 2 times: one call answers one question"},
		{"extract twice", []string{"--extract", "a", "--extract", "b"}, "--extract given 2 times: one call answers one question"},
		{"extract-all twice", []string{"--extract-all", "a", "--extract-all", "b"}, "--extract-all given 2 times: one call answers one question"},
		{"equals spelling", []string{"--diff=a", "--diff=b"}, "--diff given 2 times: one call answers one question"},
		{"once is fine", []string{"--diff", "a", "/bin/ls"}, ""},
		{"after terminator", []string{"--", "--diff", "--diff"}, ""},
		{"distinct pair refused", []string{"--diff", "a", "--explain", "b"}, "cannot be combined"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := conflictFlags()
			if err := fs.Parse(c.args); err != nil && err != flag.ErrHelp {
				t.Fatalf("parse %v: %v", c.args, err)
			}
			got := cliConflict(fs, c.args)
			if c.want == "" {
				if got != "" {
					t.Fatalf("cliConflict(%v) = %q, want no refusal", c.args, got)
				}
				return
			}
			if !strings.Contains(got, c.want) {
				t.Fatalf("cliConflict(%v) = %q, want %q", c.args, got, c.want)
			}
		})
	}
}

// The refusal has to be observable from the command line, not only from
// cliConflict: rc=2 and the count in stderr.
func TestCLIConflict(t *testing.T) {
	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"ext-op twice", []string{"--ext-op", "adb_attach", "--ext-op", "adb_detach", "/bin/ls"}, "--ext-op given 2 times"},
		{"diff twice", []string{"--diff", "/bin/ls", "--diff", "/usr/bin/true", "/bin/ls"}, "--diff given 2 times"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, stderr, code := runCLIAll(t, c.args...)
			if code != 2 {
				t.Fatalf("exit %d, want 2; stderr:\n%s", code, stderr)
			}
			if !strings.Contains(stderr, c.want) {
				t.Fatalf("stderr does not carry %q:\n%s", c.want, stderr)
			}
		})
	}
}
