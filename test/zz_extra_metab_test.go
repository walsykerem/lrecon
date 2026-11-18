package main

// metaBThunk walks one ECMA-335 method body to the `jmp [slot]` stub the CLR
// emits for a P/Invoke. These cases feed it real PE images so the section
// mapper, both body header forms and every refusal are exercised.

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func metaBThunkImage(t *testing.T, body []byte) (peImage, uint64, int) {
	t.Helper()
	b := sfPE(t, []sfSection{{name: ".text", rva: 0x1000, data: body}}, nil)
	img, ok := openPEImage(bytes.NewReader(b))
	if !ok {
		t.Fatal("openPEImage rejected the P/Invoke fixture")
	}
	base, ptr, ok := metaBPEBase(b)
	if !ok || ptr != 8 || base != 0x140000000 {
		t.Fatalf("metaBPEBase = %#x/%d/%v", base, ptr, ok)
	}
	return img, base, ptr
}

func TestMetaBThunkTinyBody(t *testing.T) {
	body := make([]byte, 32)
	body[0] = 0x02 // tiny header: size 0, one instruction
	copy(body[1:], []byte{0xff, 0x25, 0x09, 0x00, 0x00, 0x00})
	img, base, ptr := metaBThunkImage(t, body)
	slot, note, err := metaBThunk(img, 0x1000, base, ptr)
	if err != nil {
		t.Fatalf("tiny body: %v", err)
	}
	if note != "" {
		t.Fatalf("tiny body note = %q", note)
	}
	if slot.bytes != "ff 25 09 00 00 00" {
		t.Fatalf("slot bytes = %q", slot.bytes)
	}
	if want := base + 0x1010; slot.va != want {
		t.Fatalf("slot VA = %#x, want %#x", slot.va, want)
	}
}

func TestMetaBThunkFatBody(t *testing.T) {
	body := make([]byte, 32)
	// Fat header: first u16 holds (size/4)<<12 | 3; 12 bytes is the minimum.
	binary.LittleEndian.PutUint16(body[0:], (3<<12)|3)
	copy(body[12:], []byte{0xff, 0x25, 0x05, 0x00, 0x00, 0x00})
	img, base, ptr := metaBThunkImage(t, body)
	slot, note, err := metaBThunk(img, 0x1000, base, ptr)
	if err != nil {
		t.Fatalf("fat body: %v", err)
	}
	if note != "" || slot.bytes != "ff 25 05 00 00 00" {
		t.Fatalf("fat body = %+v note %q", slot, note)
	}
	if want := base + 0x1017; slot.va != want {
		t.Fatalf("fat slot VA = %#x, want %#x", slot.va, want)
	}

	binary.LittleEndian.PutUint16(body[0:], (1<<12)|3) // claims four bytes, below the minimum
	img, base, ptr = metaBThunkImage(t, body)
	if _, _, err := metaBThunk(img, 0x1000, base, ptr); err == nil || !strings.Contains(err.Error(), "declares 4 bytes") {
		t.Fatalf("short fat header error = %v", err)
	}
}

func TestMetaBThunkRefusals(t *testing.T) {
	// A body that does not start with ff 25 is named, not silently accepted.
	body := make([]byte, 32)
	body[0] = 0x02
	body[1] = 0x90
	img, base, ptr := metaBThunkImage(t, body)
	slot, note, err := metaBThunk(img, 0x1000, base, ptr)
	if err != nil {
		t.Fatalf("non-jump body: %v", err)
	}
	if slot.bytes != "90 00 00 00 00 00" || !strings.Contains(note, "jmp [slot]") {
		t.Fatalf("non-jump body = %+v note %q", slot, note)
	}

	// A header byte that is neither tiny nor fat is a refusal.
	bad := make([]byte, 8)
	img, base, ptr = metaBThunkImage(t, bad)
	if _, _, err := metaBThunk(img, 0x1000, base, ptr); err == nil || !strings.Contains(err.Error(), "not an ECMA-335 method body header") {
		t.Fatalf("bad header error = %v", err)
	}

	// A header in the last mapped byte leaves no room for the six-byte thunk.
	full := make([]byte, 0x200)
	full[0x1fb] = 0x02 // header 0x1000+0x1fb; the six-byte body crosses the end
	img, base, ptr = metaBThunkImage(t, full)
	if _, _, err := metaBThunk(img, 0x1000+0x1fb, base, ptr); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("truncated thunk error = %v", err)
	}

	// An RVA outside every section is reported before any body is read.
	if _, _, err := metaBThunk(img, 0x9000, base, ptr); err == nil || !strings.Contains(err.Error(), "outside every section") {
		t.Fatalf("outside-section error = %v", err)
	}
}

// TestMetaBThunkPE32Slot covers the 32-bit branch: the slot VA is the absolute
// displacement, not image base plus code offset.
func TestMetaBThunkPE32Slot(t *testing.T) {
	body := make([]byte, 16)
	body[0] = 0x02
	copy(body[1:], []byte{0xff, 0x25, 0x10, 0x10, 0x00, 0x00})
	b := sfPE(t, []sfSection{{name: ".text", rva: 0x1000, data: body}}, nil)
	binary.LittleEndian.PutUint16(b[0x98:], 0x10b) // PE32 optional header
	img, ok := openPEImage(bytes.NewReader(b))
	if !ok {
		t.Fatal("openPEImage rejected the PE32 fixture")
	}
	base, ptr, ok := metaBPEBase(b)
	if !ok || ptr != 4 {
		t.Fatalf("metaBPEBase(PE32) = %#x/%d/%v", base, ptr, ok)
	}
	slot, _, err := metaBThunk(img, 0x1000, base, ptr)
	if err != nil {
		t.Fatalf("PE32 body: %v", err)
	}
	if slot.va != 0x1010 {
		t.Fatalf("PE32 slot VA = %#x, want absolute 0x1010", slot.va)
	}
}
