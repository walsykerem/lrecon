package main

import (
	"debug/elf"
	"debug/macho"
	"fmt"
	"os"
)

// swiftRefl is what one reflection section yielded.
type swiftRefl struct {
	Section string   `json:"section"`
	Count   int      `json:"count"`
	Names   []string `json:"names,omitempty"`
	Skipped int      `json:"unresolved,omitempty"`
}

func init() {
	registerOp(op{
		name:  "analyze_swift_types",
		route: "L",
		needs: true,
		desc:  "count __swift5_types/__swift5_proto records and resolve descriptor names in Go",
		run: func(path string) (any, error) {
			imgs, bad, err := swiftImagesOf(path)
			if err != nil {
				return nil, err
			}
			res := struct {
				Slices     int         `json:"slices"`
				Unreadable int         `json:"unreadable_slices,omitempty"`
				Version    string      `json:"reflection_version,omitempty"`
				Sections   []swiftRefl `json:"sections"`
			}{Slices: len(imgs), Unreadable: bad, Sections: []swiftRefl{}}
			for _, img := range imgs {
				// Each slice has its own section offsets and its own address
				// range. Resolving slice 1 through slice 0's reader returns
				// bytes that look like names but are not the slice's names.
				va, err := vaReader(path, img.slice)
				if err != nil {
					return nil, err
				}
				if v, ok := swiftReflectionVersion(img.version); ok && res.Version == "" {
					res.Version = fmt.Sprintf("%d", v)
				}
				for _, s := range img.sections {
					mask, ok := swiftMask[s.name]
					if !ok {
						continue
					}
					n, size, ok := swiftSectionCount(s)
					if !ok {
						return nil, fmt.Errorf("%s:%s %d bytes is not a multiple of %d", path, s.name, len(s.data), size)
					}
					rf := swiftRefl{Section: s.name, Count: n}
					for i := 0; i+4 <= len(s.data) && len(rf.Names) < 32; i += 4 {
						name, ok := swiftDescriptorName(va, s, i, mask)
						if !ok {
							rf.Skipped++
							continue
						}
						rf.Names = append(rf.Names, name)
					}
					res.Sections = append(res.Sections, rf)
				}
			}
			return res, nil
		},
	})
}

// swiftDescriptorName follows the relative pointer at entry i to its context
// descriptor, then the descriptor's relative name pointer.
func swiftDescriptorName(va func(uint64, int) []byte, s swiftSec, i int, mask uint32) (string, bool) {
	rel := int32(u32le(s.data, i) &^ mask)
	if rel == 0 {
		return "", false
	}
	target := s.addr + uint64(i) + uint64(int64(rel))
	hdr := va(target, 12)
	if len(hdr) < 12 {
		return "", false
	}
	nameRel := int32(u32le(hdr, 8))
	b := va(target+8+uint64(int64(nameRel)), 200)
	for i, c := range b {
		if c == 0 {
			if i < 2 || !printableASCII(b[:i]) {
				return "", false
			}
			return string(b[:i]), true
		}
	}
	return "", false
}

// vaReader maps virtual addresses to file bytes through the section table of the
// requested Mach-O slice (0 for a thin file or ELF), so a fat file's slices are
// never resolved against each other's bytes.
func vaReader(path string, slice int) (func(uint64, int) []byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	type span struct {
		addr, size uint64
		off        int64
	}
	var spans []span
	if ff, err := macho.NewFatFile(f); err == nil {
		if slice < 0 || slice >= len(ff.Arches) {
			f.Close()
			return nil, fmt.Errorf("%s has no slice %d (%d slices)", path, slice, len(ff.Arches))
		}
		base := int64(ff.Arches[slice].Offset)
		for _, s := range ff.Arches[slice].File.Sections {
			spans = append(spans, span{s.Addr, s.Size, base + int64(s.Offset)})
		}
	} else if mf, err := macho.NewFile(f); err == nil {
		for _, s := range mf.Sections {
			spans = append(spans, span{s.Addr, s.Size, int64(s.Offset)})
		}
	} else if ef, err := elf.NewFile(f); err == nil {
		for _, s := range ef.Sections {
			spans = append(spans, span{s.Addr, s.Size, int64(s.Offset)})
		}
	} else {
		f.Close()
		return nil, formatRefusal(path, "is neither Mach-O nor ELF")
	}
	return func(va uint64, n int) []byte {
		for _, s := range spans {
			if va < s.addr || va >= s.addr+s.size {
				continue
			}
			// A name lives at the tail of its section: the caller asks for a
			// fixed window, so return the bytes that exist instead of failing
			// the whole read when the window runs past the section end.
			if avail := s.addr + s.size - va; uint64(n) > avail {
				n = int(avail)
			}
			if n <= 0 {
				return nil
			}
			b := make([]byte, n)
			got, err := f.ReadAt(b, s.off+int64(va-s.addr))
			if err != nil && got == 0 {
				return nil
			}
			return b[:got]
		}
		return nil
	}, nil
}
