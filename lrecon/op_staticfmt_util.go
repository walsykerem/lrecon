package main

// Shared PE reader for the static-format ops (certificates, load config,
// resources). debug/pe rejects unknown machine types, and these three ops all
// need the data-directory table, which debug/pe exposes only as typed values,
// so the header is parsed here once instead of three times.

import (
	"fmt"
	"strings"
)

const (
	peDirSecurity   = 4
	peDirResource   = 2
	peDirLoadConfig = 10
)

type peSec struct {
	name                    string
	va, vsize, off, rawSize uint32
}

type peFile struct {
	b             []byte
	pe32plus      bool
	optOff        int // optional header start
	dirOff        int // first data-directory entry
	nDirs         uint32
	sizeOfHeaders uint32
	sects         []peSec
}

func openPEBytes(b []byte) (*peFile, error) {
	if len(b) < 0x40 || b[0] != 'M' || b[1] != 'Z' {
		return nil, fmt.Errorf("no MZ header")
	}
	peOff := int(u32le(b, 0x3c))
	if peOff < 4 || peOff+24 > len(b) || string(b[peOff:peOff+4]) != "PE\x00\x00" {
		return nil, fmt.Errorf("no PE signature at %#x", peOff)
	}
	nsec := int(u16le(b, peOff+6))
	optSize := int(u16le(b, peOff+20))
	opt := peOff + 24
	if optSize < 2 || opt+optSize > len(b) {
		return nil, fmt.Errorf("optional header of %d bytes runs past the file", optSize)
	}
	p := &peFile{b: b, optOff: opt}
	switch m := u16le(b, opt); m {
	case 0x10b:
		p.dirOff = opt + 96
		p.sizeOfHeaders = u32le(b, opt+60)
	case 0x20b:
		p.pe32plus = true
		p.dirOff = opt + 112
		p.sizeOfHeaders = u32le(b, opt+60)
	default:
		return nil, fmt.Errorf("unknown optional header magic %#x", m)
	}
	if opt+optSize < p.dirOff {
		return nil, fmt.Errorf("optional header is too short for its data directories")
	}
	p.nDirs = u32le(b, p.dirOff-4)
	if max := uint32((opt + optSize - p.dirOff) / 8); p.nDirs > max {
		p.nDirs = max // the header is the authority on how many entries exist
	}
	sec := opt + optSize
	if sec+nsec*40 > len(b) {
		return nil, fmt.Errorf("section table of %d entries runs past the file", nsec)
	}
	for i := range nsec {
		s := b[sec+i*40:]
		p.sects = append(p.sects, peSec{
			name:    strings.TrimRight(string(s[:8]), "\x00"),
			vsize:   u32le(s, 8),
			va:      u32le(s, 12),
			rawSize: u32le(s, 16),
			off:     u32le(s, 20),
		})
	}
	return p, nil
}

// dir returns one data-directory entry. A missing index is an error, not a
// zero, because a PE without the directory cannot answer the question.
func (p *peFile) dir(i int) (uint32, uint32, error) {
	if i < 0 || uint32(i) >= p.nDirs {
		return 0, 0, fmt.Errorf("PE declares %d data directories, no index %d", p.nDirs, i)
	}
	o := p.dirOff + i*8
	if o+8 > len(p.b) {
		return 0, 0, fmt.Errorf("data directory %d runs past the file", i)
	}
	return u32le(p.b, o), u32le(p.b, o+4), nil
}

func (p *peFile) span(s peSec) uint64 {
	if s.rawSize > s.vsize {
		return uint64(s.rawSize)
	}
	return uint64(s.vsize)
}

// at returns the bytes backing an RVA range. Every offset comes from the file
// being parsed, so both the section span and the file length are checked.
func (p *peFile) at(rva, size uint32) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}
	if uint64(rva)+uint64(size) <= uint64(p.sizeOfHeaders) && uint64(rva)+uint64(size) <= uint64(len(p.b)) {
		return p.b[rva : uint64(rva)+uint64(size)], nil
	}
	for _, s := range p.sects {
		if rva < s.va || uint64(rva)+uint64(size) > uint64(s.va)+p.span(s) {
			continue
		}
		off := uint64(s.off) + uint64(rva-s.va)
		if off+uint64(size) > uint64(len(p.b)) {
			return nil, fmt.Errorf("rva %#x+%#x maps past the file", rva, size)
		}
		return p.b[off : off+uint64(size)], nil
	}
	return nil, fmt.Errorf("rva %#x+%#x is in no section", rva, size)
}

// fileOffset is at() for callers that report an on-disk position.
func (p *peFile) fileOffset(rva, size uint32) (uint64, error) {
	if _, err := p.at(rva, size); err != nil {
		return 0, err
	}
	if uint64(rva)+uint64(size) <= uint64(p.sizeOfHeaders) {
		return uint64(rva), nil
	}
	for _, s := range p.sects {
		if rva >= s.va && uint64(rva)+uint64(size) <= uint64(s.va)+p.span(s) {
			return uint64(s.off) + uint64(rva-s.va), nil
		}
	}
	return 0, fmt.Errorf("rva %#x is in no section", rva)
}

func (p *peFile) sectionName(rva uint32) string {
	for _, s := range p.sects {
		if rva >= s.va && uint64(rva) < uint64(s.va)+p.span(s) {
			return s.name
		}
	}
	return ""
}

// word reads one pointer-sized field: 8 bytes in PE32+, 4 in PE32.
func (p *peFile) word(b []byte, off int) (uint64, bool) {
	if p.pe32plus {
		if off+8 > len(b) {
			return 0, false
		}
		return u64le(b, off), true
	}
	if off+4 > len(b) {
		return 0, false
	}
	return uint64(u32le(b, off)), true
}
