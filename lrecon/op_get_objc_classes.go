package main

import (
	"debug/macho"
	"os"
)

// objcFixupMask keeps the low 43 bits of a chained-fixup pointer.
const objcFixupMask = 1<<43 - 1

func init() {
	registerOp(op{
		name:  "get_objc_classes",
		route: "L",
		needs: true,
		desc:  "walk __objc_classlist → class_t → class_ro_t → __objc_classname and list class names",
		run: func(path string) (any, error) {
			// class_t.data@32 → class_ro_t (low 3 bits are flags) → name@24.
			names, unresolved, err := objcNameList(path, "__objc_classlist", []int{32, 24}, true)
			if noSection(err) {
				return skipf("%s has no Objective-C class list", path), nil
			}
			if err != nil {
				return nil, err
			}
			if len(names) == 0 {
				return skipf("%s: class list carries no resolvable names", path), nil
			}
			return struct {
				Count      int      `json:"count"`
				Classes    []string `json:"classes"`
				Unresolved int      `json:"unresolved,omitempty"`
			}{Count: len(names) + unresolved, Classes: capN(uniqSorted(names), 100), Unresolved: unresolved}, nil
		},
	})
}

// objcNameList resolves the name of every object referenced by section `sect`.
// chain holds the pointer offsets to follow; the last one points at the C name.
// mask clears the low flag bits of an intermediate pointer (class_ro_t).
func objcNameList(path, sect string, chain []int, mask bool) ([]string, int, error) {
	b, _, ptr, err := machoSectionData(path, sect)
	if err != nil {
		return nil, 0, err
	}
	va, err := vaReader(path, 0)
	if err != nil {
		return nil, 0, err
	}
	base := machoImageBase(path)
	var names []string
	unresolved := 0
	for i := 0; i+ptr <= len(b); i += ptr {
		raw := uint64(u32le(b, i))
		if ptr == 8 {
			raw = u64le(b, i)
		}
		s, ok := objcResolveName(va, ptr, chain, mask, raw, base)
		if !ok {
			unresolved++
			continue
		}
		names = append(names, s)
	}
	return names, unresolved, nil
}

// objcResolveName tries the raw pointer first and then the dyld chained-fixup
// encodings: a 43-bit image offset, and that offset plus the __TEXT vmaddr.
func objcResolveName(va func(uint64, int) []byte, ptr int, chain []int, mask bool, raw, base uint64) (string, bool) {
	cands := []uint64{raw}
	// The rebased form is tried even when the high (next/high8) bits are
	// zero: a chained pointer whose next field is 0 has the plain offset in
	// the low bits and needs the image base added, not a high-bits test.
	cands = append(cands, base+raw&objcFixupMask, raw&objcFixupMask)
	for _, c := range cands {
		if s, ok := objcFollow(va, ptr, chain, mask, c, base); ok {
			return s, true
		}
	}
	return "", false
}

func objcFollow(va func(uint64, int) []byte, ptr int, chain []int, mask bool, cur, base uint64) (string, bool) {
	for depth, off := range chain {
		o := off
		if ptr == 4 {
			o = off / 2
		}
		next, ok := objcReadPtr(va, ptr, cur+uint64(o), base)
		if !ok || next == 0 {
			return "", false
		}
		if mask && depth == 0 {
			next &^= 7
		}
		cur = next
	}
	body := va(cur, 200)
	if len(body) == 0 {
		return "", false
	}
	s, ok := cstr(body, 0)
	if !ok {
		return "", false
	}
	return s, true
}

// objcReadPtr reads one pointer, falling back to the chained-fixup decode when
// the plain value does not map to file bytes.
func objcReadPtr(va func(uint64, int) []byte, ptr int, at, base uint64) (uint64, bool) {
	w := va(at, ptr)
	if len(w) < ptr {
		return 0, false
	}
	raw := uint64(u32le(w, 0))
	if ptr == 8 {
		raw = u64le(w, 0)
	}
	// One mapped byte is the test: a target at the very end of its section
	// (a short name such as "Gadget") cannot supply a whole pointer-sized
	// window, and demanding one made the last class in a section unresolved.
	if len(va(raw, 1)) == 1 {
		return raw, true
	}
	if off := raw & objcFixupMask; off != 0 {
		if len(va(base+off, 1)) == 1 {
			return base + off, true
		}
		if len(va(off, 1)) == 1 {
			return off, true
		}
	}
	return raw, true
}

// machoImageBase returns the vmaddr of the __TEXT segment of the first slice.
func machoImageBase(path string) uint64 {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	var mf *macho.File
	if ff, ferr := macho.NewFatFile(f); ferr == nil && len(ff.Arches) > 0 {
		mf = ff.Arches[0].File
	} else if tf, terr := macho.NewFile(f); terr == nil {
		mf = tf
	}
	if mf == nil {
		return 0
	}
	for _, l := range mf.Loads {
		if seg, ok := l.(*macho.Segment); ok && seg.Name == "__TEXT" {
			return seg.Addr
		}
	}
	return 0
}
