package main

import (
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

func init() {
	registerOp(op{
		name:  "inspect_kernel_module",
		route: "L",
		needs: true,
		desc:  "kernel module metadata: Linux .modinfo key=value pairs, or the Mach-O __kmod_info name/version record",
		run: func(path string) (any, error) {
			b := head(path, 512)
			if b == nil {
				return nil, fmt.Errorf("%s cannot be read", path)
			}
			switch {
			case len(b) >= 4 && string(b[:4]) == "\x7fELF":
				return linuxModinfo(path)
			case isMachO(b) || isFatMachO(b):
				return machoKmod(path)
			}
			return nil, fmt.Errorf("%s is neither ELF nor Mach-O", path)
		},
	})
}

// linuxModinfo reads the .modinfo string table of a loadable Linux module.
func linuxModinfo(path string) (any, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s is not ELF: %w", path, err)
	}
	defer f.Close()
	sec := f.Section(".modinfo")
	if sec == nil {
		return skipf("%s has no .modinfo section (not a loadable module)", path), nil
	}
	data, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("%s .modinfo is not readable: %w", path, err)
	}
	type pair struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	res := struct {
		OS     string `json:"os"`
		Module string `json:"module,omitempty"`
		Bytes  int    `json:"bytes"`
		Total  int    `json:"fields_total"`
		Fields []pair `json:"fields"`
	}{OS: "linux", Bytes: len(data)}
	for s := range strings.SplitSeq(string(data), "\x00") {
		k, v, ok := strings.Cut(s, "=")
		if !ok || k == "" {
			continue
		}
		if k == "name" {
			res.Module = v
		}
		res.Total++
		// The listing is capped; fields_total keeps the count honest.
		if len(res.Fields) < 32 {
			res.Fields = append(res.Fields, pair{k, v})
		}
	}
	if len(res.Fields) == 0 {
		return nil, fmt.Errorf("%s .modinfo carries no key=value pairs", path)
	}
	return res, nil
}

// machoKmod reads the kmod_info record a kext exports in __kmod_info.
func machoKmod(path string) (any, error) {
	data, ptr, err := machoKmodRecord(path)
	if err != nil {
		if noSection(err) {
			return skipf("%s has no kmod_info record (not a kext)", path), nil
		}
		return nil, err
	}
	// struct kmod_info { next*, info_version int32, id uint32, name[64], version[64], ... }
	if len(data) < ptr+8+128 {
		return nil, fmt.Errorf("%s __kmod_info must be at least %d bytes for a kmod_info record, is %d", path, ptr+8+128, len(data))
	}
	// info_version and id sit right behind the next pointer, whatever its width.
	version := int32(binary.LittleEndian.Uint32(data[ptr:]))
	id := binary.LittleEndian.Uint32(data[ptr+4:])
	off := ptr + 8
	name, _ := cstr(data, off)
	ver, _ := cstr(data, off+64)
	if name == "" {
		return nil, fmt.Errorf("%s __kmod_info has no name in its record (empty field)", path)
	}
	return struct {
		OS      string `json:"os"`
		Name    string `json:"name"`
		Version string `json:"version,omitempty"`
		InfoVer int32  `json:"info_version"`
		ID      uint32 `json:"id"`
		Bytes   int    `json:"kmod_info_bytes"`
	}{"macos", name, ver, version, id, len(data)}, nil
}

// machoKmodRecord returns the bytes of one kmod_info record and the pointer
// width of the image. A kext built with a __kmod_info section hands it over
// directly; one built with an older toolchain (the shipping HighPoint kexts do
// this) keeps `_kmod_info` as a symbol in __DATA,__data, and the record is the
// 8/4-byte next pointer, info_version, id, name[64] and version[64].
func machoKmodRecord(path string) ([]byte, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	var mf *macho.File
	var base int64
	if ff, ferr := macho.NewFatFile(f); ferr == nil && len(ff.Arches) > 0 {
		mf, base = ff.Arches[0].File, int64(ff.Arches[0].Offset)
	} else if tf, terr := macho.NewFile(f); terr == nil {
		mf = tf
	} else {
		return nil, 0, fmt.Errorf("%s is not Mach-O", path)
	}
	ptr := 4
	if mf.Magic == macho.Magic64 {
		ptr = 8
	}
	for _, s := range mf.Sections {
		if s.Name != "__kmod_info" {
			continue
		}
		if s.Size > opMaxFile {
			return nil, 0, fmt.Errorf("%s __kmod_info must be under the %d-byte read cap, is %d bytes", path, int64(opMaxFile), s.Size)
		}
		b := make([]byte, s.Size)
		if _, rerr := f.ReadAt(b, base+int64(s.Offset)); rerr != nil && len(b) > 0 {
			return nil, 0, fmt.Errorf("%s: reading __kmod_info: %w", path, rerr)
		}
		return b, ptr, nil
	}
	if mf.Symtab == nil {
		return nil, 0, fmt.Errorf("%s has no __kmod_info section and no symbol table", path)
	}
	need := uint64(ptr) + 8 + 128
	for _, s := range mf.Symtab.Syms {
		if s.Name != "_kmod_info" {
			continue
		}
		// The symtab keeps an undefined reference (n_type N_UNDF=0, value 0)
		// next to the defined record; only the defined one has bytes.
		if s.Type&0x0e == 0 || s.Value == 0 {
			continue
		}
		for _, sec := range mf.Sections {
			if sec == nil || s.Value < sec.Addr || s.Value+need > sec.Addr+sec.Size {
				continue
			}
			b := make([]byte, need)
			if _, rerr := f.ReadAt(b, base+int64(sec.Offset)+int64(s.Value-sec.Addr)); rerr != nil {
				return nil, 0, fmt.Errorf("%s: reading _kmod_info: %w", path, rerr)
			}
			return b, ptr, nil
		}
		return nil, 0, fmt.Errorf("%s is not a readable kext: _kmod_info at %#x is in no segment", path, s.Value)
	}
	return nil, 0, fmt.Errorf("%s has no __kmod_info section and no _kmod_info symbol", path)
}
