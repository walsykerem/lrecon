package main

// Bucket 20's angle: the read-only listings are honest about *what they read*.
// Every listing in this bucket that needs a decompiler refuses a Go source file
// with the detected kind in the message and without consulting the engine at
// all, the pure-Go string lister refuses it as a format error, and the
// live-injection op ignores the target instead of pretending to analyse it.
// On a real binary, list_segments' block count is checked against an
// independent debug/macho walk (the blocks tile every segment's memsz exactly),
// and every list_strings row's bytes and address are recomputed from the file.
// Finally the Ghidra cache key is proven content-addressed: a same-size,
// same-mtime rewrite of the target cannot be served the previous answer.

import (
	"debug/macho"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// b20Native is the independent Mach-O view the assertions compare against.
type b20Native struct {
	base     uint64
	sections []*macho.Section
	segs     []b20SegInfo
}

type b20SegInfo struct {
	name   string
	addr   uint64
	memsz  uint64
	filesz uint64
	off    uint64
}

// b20ParseMacho reads the first slice, the slice Ghidra imports.
func b20ParseMacho(t *testing.T, path string) b20Native {
	t.Helper()
	var n b20Native
	fat, ferr := macho.OpenFat(path)
	var f *macho.File
	switch ferr {
	case nil:
		t.Cleanup(func() { fat.Close() })
		f = fat.Arches[0].File
		n.base = uint64(fat.Arches[0].Offset)
	default:
		thin, terr := macho.Open(path)
		if terr != nil {
			t.Fatalf("%s is not Mach-O: fat=%v thin=%v", path, ferr, terr)
		}
		t.Cleanup(func() { thin.Close() })
		f = thin
	}
	n.sections = f.Sections
	for _, l := range f.Loads {
		s, ok := l.(*macho.Segment)
		if !ok || s == nil {
			continue
		}
		n.segs = append(n.segs, b20SegInfo{s.Name, s.Addr, s.Memsz, s.Filesz, uint64(s.Offset)})
	}
	if len(n.sections) == 0 || len(n.segs) == 0 {
		t.Fatalf("%s: independent parse found %d sections, %d segments", path, len(n.sections), len(n.segs))
	}
	return n
}

type b20SegRow struct {
	Name  string `json:"name"`
	Start string `json:"start"`
	End   string `json:"end"`
	Size  uint64 `json:"size"`
	Perms string `json:"perms"`
}

type b20Segs struct {
	Blocks   int         `json:"blocks"`
	Bytes    uint64      `json:"bytes"`
	Segments []b20SegRow `json:"segments"`
}

func b20Hex(t *testing.T, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X"), 16, 64)
	if err != nil {
		t.Fatalf("address %q is not hex: %v", s, err)
	}
	return v
}

// TestTur7Bucket20WrongTargetAndStaleCache drives one honest listing per shape
// in this bucket: wrong target for every op, then real values cross-checked
// against an independent parse, then the cache's content key.
func TestTur7Bucket20WrongTargetAndStaleCache(t *testing.T) {
	const native = "/bin/ls"
	if d, err := Probe(native); err != nil || d.Kind != "macho" {
		t.Fatalf("%s must be Mach-O for this test: kind=%q err=%v", native, d.Kind, err)
	}

	t.Run("wrong-target", func(t *testing.T) {
		// failGhidra makes any engine consultation a test failure: a text
		// target's refusal must come from the kind guard, not from Ghidra.
		failGhidra(t)
		dir := t.TempDir()
		src := filepath.Join(dir, "listing.go")
		payload := []byte("package main\n\nfunc main() { println(\"not machine code\") }\n")
		if err := os.WriteFile(src, payload, 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		if d, err := Probe(src); err != nil || d.Kind != "text" {
			t.Fatalf("fixture kind = %q (%v), want text", d.Kind, err)
		}
		for _, name := range []string{"list_names", "list_procedures", "list_segments", "list_unknowns", "match_native_functions"} {
			res, err := runOp(name, src)
			if err != nil {
				t.Fatalf("%s on a Go file returned error %v, want the kind refusal", name, err)
			}
			s, ok := res.(*skip)
			if !ok {
				t.Fatalf("%s on a Go file answered %T (%v), want *skip", name, res, res)
			}
			if !strings.HasPrefix(s.Reason, "text: no decompiler kind here") {
				t.Fatalf("%s refusal %q does not name the detected kind", name, s.Reason)
			}
			if strings.Contains(s.Reason, "not installed") || strings.Contains(s.Reason, "analyzeHeadless") {
				t.Fatalf("%s blamed the engine for a wrong target: %q", name, s.Reason)
			}
		}

		// The same refusal must reach the CLI contract, not only the op body:
		// kind no_engine names the detected kind in the error, never a missing
		// decompiler.
		for _, name := range []string{"list_names", "list_procedures", "list_segments", "list_unknowns", "match_native_functions"} {
			stdout, _, code := runCLIAll(t, "--op", name, src)
			if code != 2 {
				t.Fatalf("%s exit = %d, want 2\n%s", name, code, stdout)
			}
			var env struct {
				Error string `json:"error"`
				Kind  string `json:"kind"`
			}
			if err := json.Unmarshal([]byte(stdout), &env); err != nil {
				t.Fatalf("%s stdout is not an envelope: %v\n%s", name, err, stdout)
			}
			if env.Kind != string(kindNoEngine) || !strings.HasPrefix(env.Error, "text: no decompiler kind here") {
				t.Fatalf("%s CLI refusal = %q/%q, want the text kind refusal under no_engine", name, env.Kind, env.Error)
			}
		}

		// list_strings is a reader, not a decompiler op: it owes a format
		// refusal that names what it can read, and still names the target.
		res, err := runOp("list_strings", src)
		if err == nil {
			t.Fatalf("list_strings on a Go file answered %T, want a format refusal", res)
		}
		if got := classify(err.Error()); got != kindBadArg {
			t.Fatalf("list_strings refusal kind = %s (%q), want %s", got, err, kindBadArg)
		}
		for _, want := range []string{"is not ELF, Mach-O or PE", src} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("list_strings refusal %q does not name %q", err, want)
			}
		}
	})

	t.Run("segments-tile-macho-segments", func(t *testing.T) {
		res, err := runOp("list_segments", native)
		if err != nil {
			t.Fatalf("list_segments on %s: %v", native, err)
		}
		m, ok := res.(map[string]any)
		if !ok {
			t.Fatalf("list_segments answered %T, want a map", res)
		}
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		var got b20Segs
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		ind := b20ParseMacho(t, native)
		if got.Blocks != len(got.Segments) {
			t.Fatalf("blocks = %d, rows = %d: the count must be the number of listed blocks", got.Blocks, len(got.Segments))
		}
		rows := got.Segments
		sort.Slice(rows, func(i, j int) bool {
			return b20Hex(t, rows[i].Start) < b20Hex(t, rows[j].Start)
		})

		// Every block must lie inside a real segment, and the blocks of one
		// segment must tile its memsz exactly: no gap, no overlap, no invented
		// span. That is the hand check on the block count.
		tiled := 0
		for _, seg := range ind.segs {
			if seg.memsz == 0 || seg.name == "__PAGEZERO" {
				continue
			}
			end := seg.addr + seg.memsz - 1
			var tiles []b20SegRow
			for _, r := range rows {
				start, rend := b20Hex(t, r.Start), b20Hex(t, r.End)
				if start >= seg.addr && start <= end {
					if rend > end {
						t.Fatalf("block %s %#x-%#x runs past segment %s end %#x", r.Name, start, rend, seg.name, end)
					}
					tiles = append(tiles, r)
				}
			}
			if len(tiles) == 0 {
				t.Fatalf("segment %s %#x-%#x has no blocks", seg.name, seg.addr, end)
			}
			if b20Hex(t, tiles[0].Start) != seg.addr {
				t.Fatalf("segment %s starts at %#x, first block starts at %s", seg.name, seg.addr, tiles[0].Start)
			}
			for i := 1; i < len(tiles); i++ {
				if b20Hex(t, tiles[i].Start) != b20Hex(t, tiles[i-1].End)+1 {
					t.Fatalf("segment %s: %s ends %s but %s starts %s", seg.name, tiles[i-1].Name, tiles[i-1].End, tiles[i].Name, tiles[i].Start)
				}
			}
			if last := b20Hex(t, tiles[len(tiles)-1].End); last != end {
				t.Fatalf("segment %s ends %#x, last block ends %#x", seg.name, end, last)
			}
			tiled += len(tiles)
		}

		var total uint64
		ext := 0
		for _, r := range rows {
			total += r.Size
			if r.Size != b20Hex(t, r.End)-b20Hex(t, r.Start)+1 {
				t.Fatalf("block %s size %d disagrees with %s-%s", r.Name, r.Size, r.Start, r.End)
			}
			if len(r.Perms) != 3 {
				t.Fatalf("block %s perms %q is not rwx triple", r.Name, r.Perms)
			}
			if r.Name == "EXTERNAL" {
				// Ghidra materialises thunks at a free page past the last
				// segment; it is the one block allowed outside a segment.
				ext++
				continue
			}
			if b20Hex(t, r.Start) < ind.segs[1].addr {
				t.Fatalf("block %s starts below the image base", r.Name)
			}
		}
		if tiled+ext != len(rows) {
			t.Fatalf("%d tiled + %d external != %d rows: some block belongs to no segment", tiled, ext, len(rows))
		}
		if got.Bytes != total {
			t.Fatalf("bytes = %d, sum of block sizes = %d", got.Bytes, total)
		}

		// Every Mach-O section must appear as a block with its exact start,
		// its size covered, and the exec bit derived from its flags.
		key := func(name string, addr uint64) string { return fmt.Sprintf("%s@%#x", name, addr) }
		byKey := map[string]b20SegRow{}
		for _, r := range rows {
			byKey[key(r.Name, b20Hex(t, r.Start))] = r
		}
		for _, s := range ind.sections {
			r, ok := byKey[key(s.Name, s.Addr)]
			if !ok {
				t.Fatalf("section %s at %#x has no block", s.Name, s.Addr)
			}
			if r.Size < s.Size {
				t.Fatalf("section %s block size %d < section size %d", s.Name, r.Size, s.Size)
			}
			exec := s.Flags&0x80000000 != 0
			if exec != strings.Contains(r.Perms, "x") {
				t.Fatalf("section %s flags %#x give exec=%v but block perms %q", s.Name, s.Flags, exec, r.Perms)
			}
		}
	})

	t.Run("strings-bytes-and-addresses", func(t *testing.T) {
		res, err := runOp("list_strings", native)
		if err != nil {
			t.Fatalf("list_strings on %s: %v", native, err)
		}
		m, ok := res.(map[string]any)
		if !ok {
			t.Fatalf("list_strings answered %T, want a map", res)
		}
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		var got struct {
			Strings          int    `json:"strings"`
			Total            int    `json:"total"`
			Shown            int    `json:"shown"`
			Truncated        bool   `json:"truncated"`
			StringsTruncated bool   `json:"strings_truncated"`
			Scanned          uint64 `json:"scanned"`
			ScannedWhole     bool   `json:"scanned_whole"`
			Rows             []struct {
				Address uint64 `json:"address"`
				Off     uint64 `json:"file_offset"`
				Len     int    `json:"len"`
				Value   string `json:"value"`
				ASCII   bool   `json:"ascii"`
			} `json:"rows"`
		}
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		if got.Strings != got.Total {
			t.Fatalf("strings = %d, total = %d: the two names must be one count", got.Strings, got.Total)
		}
		if got.Shown != len(got.Rows) || got.Shown == 0 {
			t.Fatalf("shown = %d, rows = %d", got.Shown, len(got.Rows))
		}
		if got.Truncated != (got.Total > got.Shown || got.StringsTruncated) {
			t.Fatalf("truncated = %v but total=%d shown=%d value-cut=%v", got.Truncated, got.Total, got.Shown, got.StringsTruncated)
		}
		if got.ScannedWhole != (got.Scanned < nativeScanCap) {
			t.Fatalf("scanned_whole = %v with scanned = %d, cap %d", got.ScannedWhole, got.Scanned, uint64(nativeScanCap))
		}

		file, err := os.ReadFile(native)
		if err != nil {
			t.Fatal(err)
		}
		ind := b20ParseMacho(t, native)
		for _, r := range got.Rows {
			var n int
			if r.ASCII {
				n = r.Len
			} else {
				// A UTF-16LE row's len is characters, its bytes are 2x.
				n = 2 * r.Len
			}
			if r.Off+uint64(n) > uint64(len(file)) {
				t.Fatalf("row %q offset %#x len %d runs past the file", r.Value, r.Off, n)
			}
			b := file[r.Off : r.Off+uint64(n)]
			if r.ASCII {
				for i := 0; i < n && i < len(r.Value); i++ {
					if b[i] != r.Value[i] {
						t.Fatalf("row %q byte %d at %#x is %#x, not %q", r.Value, i, r.Off+uint64(i), b[i], r.Value[i])
					}
				}
				if r.Len <= listStringsValueMax && len(r.Value) != r.Len {
					t.Fatalf("row %q len = %d, value has %d bytes", r.Value, r.Len, len(r.Value))
				}
			} else {
				for i := 0; i < r.Len && i < len(r.Value); i++ {
					if b[2*i] != r.Value[i] || b[2*i+1] != 0 {
						t.Fatalf("row %q char %d at %#x is %#x %#x, want %q and NUL", r.Value, i, r.Off+uint64(2*i), b[2*i], b[2*i+1], r.Value[i])
					}
				}
			}
			// The address must be the file offset translated through the
			// section (or segment) that really holds those bytes.
			want, found := b20Addr(ind, r.Off)
			if !found {
				t.Fatalf("row %q offset %#x belongs to no section or segment", r.Value, r.Off)
			}
			if want != r.Address {
				t.Fatalf("row %q at offset %#x: address %#x, independent parse says %#x", r.Value, r.Off, r.Address, want)
			}
		}
	})

	t.Run("cache-key-is-content-addressed", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		first := []byte("first-bytes-0123456789")
		second := []byte("other-bytes-0123456789")
		if len(first) != len(second) {
			t.Fatal("fixture halves must be the same size")
		}
		same := time.Unix(1700000000, 0)
		if err := os.WriteFile(target, first, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(target, same, same); err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		copyPath := filepath.Join(dir, "copy")
		if err := os.WriteFile(copyPath, first, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(copyPath, same, same); err != nil {
			t.Fatal(err)
		}
		stCopy, err := os.Stat(copyPath)
		if err != nil {
			t.Fatal(err)
		}
		keyFirst := ghidraEntryKey(target, "12.1.4", st)
		if got := ghidraEntryKey(copyPath, "12.1.4", stCopy); got != keyFirst {
			t.Fatalf("same bytes keyed %q and %q: the entry is path-addressed, not content-addressed", keyFirst, got)
		}
		fallbackFirst := ghidraCacheKey(target, st)
		if err := os.WriteFile(target, second, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(target, same, same); err != nil {
			t.Fatal(err)
		}
		stSecond, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		if fallbackSecond := ghidraCacheKey(target, stSecond); fallbackSecond != fallbackFirst {
			t.Fatalf("fallback key changed (%q -> %q): size and mtime did not stay equal, the probe proves nothing", fallbackFirst, fallbackSecond)
		}
		if keySecond := ghidraEntryKey(target, "12.1.4", stSecond); keySecond == keyFirst {
			t.Fatalf("rewritten target kept entry key %q: a stale analysis would be served", keySecond)
		}

		// End to end: the shim reports the target's cksum, so an answer can
		// only be current if the cache re-imported the new bytes.
		runs := filepath.Join(dir, "runs.log")
		shim := ghidraShim(t, dir, fmt.Sprintf(`echo run >> %q
for a in "$@"; do out="$a"; done
printf '{"digest":"%%s"}' "$(cksum < %q | cut -d' ' -f1)" > "$out"
`, runs, target))
		t.Setenv("LRECON_GHIDRA_TIMEOUT", "20s")
		root := filepath.Join(dir, "cache")
		r1, mode1, err := ghidraCachedRun(shim, root, target, "12.1.4", "list_segments", stSecond, nil)
		if err != nil || mode1 != "fresh" {
			t.Fatalf("first run on new bytes = %q,%v; want a fresh import", mode1, err)
		}
		// Same bytes again: the entry must answer without a run.
		r2, mode2, err := ghidraCachedRun(shim, root, target, "12.1.4", "list_segments", stSecond, nil)
		if err != nil || mode2 != "cached" || fmt.Sprint(r2["digest"]) != fmt.Sprint(r1["digest"]) {
			t.Fatalf("repeat = %q,%v digest %v; want the stored answer %v", mode2, err, r2["digest"], r1["digest"])
		}
		// Rewrite back to the first bytes at the same size and mtime: the
		// stored answer must not be served for them.
		if err := os.WriteFile(target, first, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(target, same, same); err != nil {
			t.Fatal(err)
		}
		stBack, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		if got := ghidraCacheKey(target, stBack); got != fallbackFirst {
			t.Fatalf("fallback key after restoring size/mtime = %q, want %q", got, fallbackFirst)
		}
		r3, mode3, err := ghidraCachedRun(shim, root, target, "12.1.4", "list_segments", stBack, nil)
		if err != nil {
			t.Fatalf("run after rewrite: %v", err)
		}
		if mode3 == "cached" && fmt.Sprint(r3["digest"]) == fmt.Sprint(r1["digest"]) {
			t.Fatalf("stale answer served after the target's bytes changed: digest %v", r3["digest"])
		}
		if fmt.Sprint(r3["digest"]) == fmt.Sprint(r1["digest"]) {
			t.Fatalf("answer digest %v is the second revision's, want the restored bytes'", r3["digest"])
		}
		log, err := os.ReadFile(runs)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Count(string(log), "run\n"); got != 2 {
			t.Fatalf("headless runs = %d, want one per distinct content", got)
		}
	})

	t.Run("live-op-ignores-target", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "hook.go")
		if err := os.WriteFile(src, []byte("package main\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		stdout, _, code := runCLIAll(t, "--op", "load_frida_script", src)
		if code != 2 {
			t.Fatalf("load_frida_script exit = %d, want 2", code)
		}
		var env struct {
			Error string `json:"error"`
			Kind  string `json:"kind"`
		}
		if err := json.Unmarshal([]byte(stdout), &env); err != nil {
			t.Fatalf("stdout is not the refusal envelope: %v\n%s", err, stdout)
		}
		if env.Kind != string(kindOutOfScope) || env.Error != liveFridaSessionDecline {
			t.Fatalf("load_frida_script refusal = %q/%q, want out_of_scope with the live-session decline", env.Kind, env.Error)
		}
		if strings.Contains(strings.ToLower(env.Error), "decompiler") || strings.Contains(env.Error, "text") {
			t.Fatalf("live refusal judged the static target instead of refusing the live half: %q", env.Error)
		}
	})
}

// b20Addr translates a file offset into an address using the independent
// Mach-O image: the containing section first, the file-backed segment second.
func b20Addr(n b20Native, off uint64) (uint64, bool) {
	for _, s := range n.sections {
		if s.Size == 0 || s.Offset == 0 {
			continue
		}
		start := n.base + uint64(s.Offset)
		if off >= start && off < start+s.Size {
			return s.Addr + (off - start), true
		}
	}
	for _, s := range n.segs {
		if s.filesz == 0 {
			continue
		}
		start := n.base + s.off
		if off >= start && off < start+s.filesz {
			return s.addr + (off - start), true
		}
	}
	return 0, false
}
