package main

// Regression tests for the session and navigation items against a real
// universal Mach-O. The bug they pin: a fat slice's section offsets are
// relative to the slice, so every read addressed "the text section" landed in
// the fat header instead of the code, and the cursor path and binary_session
// each treated the other's session.json as a foreign artifact.

import (
	"bytes"
	"debug/macho"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// universalFixture returns the tracked fat Mach-O. It used to borrow a host
// system binary, which made these tests macOS-only for no reason.
func universalFixture(t *testing.T) string {
	t.Helper()
	ff, err := macho.OpenFat(fixtureFat)
	if err != nil {
		t.Fatalf("%s is not a fat Mach-O: %v", fixtureFat, err)
	}
	ff.Close()
	return fixtureFat
}

func firstSegment(t *testing.T, path string) (*macho.FatFile, *macho.Segment) {
	t.Helper()
	ff, err := macho.OpenFat(path)
	if err != nil {
		t.Fatalf("OpenFat(%s): %v", path, err)
	}
	t.Cleanup(func() { ff.Close() })
	for _, l := range ff.Arches[0].File.Loads {
		if seg, ok := l.(*macho.Segment); ok && seg.Filesz > 0 {
			return ff, seg
		}
	}
	t.Fatalf("%s has no file-backed segment", path)
	return nil, nil
}

func TestFatMachOSectionOffsetsAreFileAbsolute(t *testing.T) {
	path := universalFixture(t)
	ff, err := macho.OpenFat(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ff.Close()
	slice := ff.Arches[0]

	_, secs, err := nativeSections(path)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]*macho.Section{}
	for _, s := range slice.File.Sections {
		byName[s.Seg+","+s.Name] = s
	}
	checked := 0
	for _, got := range secs {
		want, ok := byName[got.Name]
		if !ok || want.Offset == 0 || want.Size == 0 {
			continue
		}
		// Section.Data() reads through the slice reader, so it is the ground
		// truth for the same bytes; got.Off must point at them in the file.
		data, derr := want.Data()
		if derr != nil || len(data) < 16 {
			continue
		}
		head := make([]byte, 16)
		f, oerr := os.Open(path)
		if oerr != nil {
			t.Fatal(oerr)
		}
		n, _ := f.ReadAt(head, int64(got.Off))
		f.Close()
		if n != len(head) || !bytes.Equal(head, data[:len(head)]) {
			t.Fatalf("%s: section offset %#x does not point at the section bytes (slice base %#x, section offset %#x)",
				got.Name, got.Off, slice.Offset, want.Offset)
		}
		checked++
	}
	if checked == 0 {
		t.Fatalf("%s: no section was comparable", path)
	}
}

func TestAddressMapFallsBackToSegment(t *testing.T) {
	path := universalFixture(t)
	ff, seg := firstSegment(t, path)
	sliceBase := uint64(ff.Arches[0].Offset)

	off, mapped, mapping := mapAddress(path, seg.Addr)
	if mapped == nil || mapping != "segment" {
		t.Fatalf("mapAddress(%#x) = %v, %q; want the __TEXT segment (image base is in no section)", seg.Addr, mapped, mapping)
	}
	if want := sliceBase + seg.Offset; off != want {
		t.Fatalf("mapAddress(%#x) file offset = %#x, want %#x", seg.Addr, off, want)
	}
	got := make([]byte, 4)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := f.ReadAt(got, int64(off))
	f.Close()
	data, err := seg.Data()
	if err != nil || n != 4 {
		t.Fatalf("read %d bytes at %#x: %v", n, off, err)
	}
	if !bytes.Equal(got, data[:4]) {
		t.Fatalf("bytes at %#x = % x, want % x", off, got, data[:4])
	}
}

func TestReadBytesPastEOFIsAnError(t *testing.T) {
	path := universalFixture(t)
	t.Setenv("LRECON_AT", "0xffffffffffff")
	t.Setenv("LRECON_LEN", "16")
	if _, err := ops["read_bytes"].run(path); err == nil {
		t.Fatal("read_bytes past the end of the file answered a success envelope instead of an error")
	}
}

func TestAnnotateFileOffsetAddsSliceBase(t *testing.T) {
	path := universalFixture(t)
	ff, err := macho.OpenFat(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ff.Close()
	slice := ff.Arches[0]
	var text *macho.Section
	for _, s := range slice.File.Sections {
		if s.Seg == "__TEXT" && s.Name == "__text" {
			text = s
		}
	}
	if text == nil {
		t.Fatalf("%s has no __TEXT,__text", path)
	}
	wantOff, mapped, _ := mapAddress(path, text.Addr)
	if mapped == nil || mapped.Name != "__TEXT,__text" {
		t.Fatalf("mapAddress(%#x) = %v", text.Addr, mapped)
	}
	res := map[string]any{"file_offset": float64(text.Offset)}
	out := annotateFileOffset(path, text.Addr, res).(map[string]any)
	if out["file_offset_in_file"] != wantOff {
		t.Fatalf("file_offset_in_file = %v, want %#x", out["file_offset_in_file"], wantOff)
	}
	if out["slice_offset"] != uint64(slice.Offset) {
		t.Fatalf("slice_offset = %v, want %#x", out["slice_offset"], slice.Offset)
	}
}

func TestSessionPathHonorsStateDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("LRECON_STATE", dir)
	t.Setenv("LRECON_SESSION", "")
	if got, want := sessionPath(), filepath.Join(dir, "session.json"); got != want {
		t.Fatalf("sessionPath() = %q, want %q (LRECON_STATE must isolate the cursor too)", got, want)
	}
}

func TestSessionAndBinarySessionShareOneFile(t *testing.T) {
	state := t.TempDir()
	t.Setenv("LRECON_STATE", state)
	t.Setenv("LRECON_SESSION", "")
	path := universalFixture(t)
	// A cursor inside a real function: the image base is below the first
	// function start, so current_procedure would find nothing there.
	fns, err := nativeFunctions(path)
	if err != nil || len(fns) == 0 {
		t.Fatalf("nativeFunctions(%s) = %d, %v", path, len(fns), err)
	}
	cursor := fns[len(fns)/2].Start + 1

	if _, err := ops["binary_session"].run(path); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LRECON_AT", fmt.Sprintf("0x%x", cursor))
	if _, err := ops["goto_address"].run(path); err != nil {
		t.Fatalf("goto_address(%#x): %v", cursor, err)
	}
	proc, err := ops["current_procedure"].run("")
	if err != nil {
		t.Fatal(err)
	}
	if pm := proc.(map[string]any); pm["found"] != true || pm["document"] != mustAbs(t, path) {
		t.Fatalf("current_procedure after goto = %v, want found=true on %s", pm, path)
	}
	// The navigation write must not make binary_session treat the file as
	// foreign: same file, same schema, so the reopen persists.
	res, err := ops["binary_session"].run(path)
	if err != nil {
		t.Fatal(err)
	}
	bm := res.(map[string]any)
	if bm["session_persisted"] != true || bm["state"] != "reopened" {
		t.Fatalf("binary_session after goto = %v, want persisted reopen", bm)
	}
	if _, err := ops["close_binary"].run(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(state, "session.json")); !os.IsNotExist(err) {
		t.Fatalf("close_binary left %s behind: %v", filepath.Join(state, "session.json"), err)
	}
}

// A navigation item takes an optional target. When one is passed it must be the
// session document: answering about another file is worse than refusing, and
// the refusal has to read as bad_arg so the caller fixes the argument instead of
// hunting a crash.
func TestAddressNavRefusesAnotherDocument(t *testing.T) {
	state := t.TempDir()
	t.Setenv("LRECON_STATE", state)
	t.Setenv("LRECON_SESSION", "")
	path := universalFixture(t)
	_, seg := firstSegment(t, path)
	t.Setenv("LRECON_AT", fmt.Sprintf("0x%x", seg.Addr))
	if _, err := ops["goto_address"].run(path); err != nil {
		t.Fatal(err)
	}
	other := writeTemp(t, "other.bin", []byte("not the session document"))
	for _, name := range []string{"next_address", "prev_address"} {
		if _, err := ops[name].run(other); err == nil {
			t.Fatalf("%s answered for %s while the session is on %s", name, other, path)
		} else if got := classify(err.Error()); got != kindBadArg {
			t.Fatalf("%s foreign document = %s (%v), want bad_arg", name, got, err)
		}
		if _, err := ops[name].run(path); err != nil {
			t.Fatalf("%s on the session document: %v", name, err)
		}
	}
}
