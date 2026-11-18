package main

import "fmt"

// IMAGE_LOAD_CONFIG_DIRECTORY32/64 field offsets. The 64-bit form is not just
// the 32-bit form with wider pointers: every field after SecurityCookie shifts,
// so the two layouts are kept apart.
type peLCLayout struct {
	cookie, sehTable, sehCount, guardCheck, cfTable, cfCount int
	guardFlags, dynamicReloc, ehTable, ehCount, hotPatch     int
	ptr                                                      int
}

var peLC32 = peLCLayout{
	cookie: 0x3C, sehTable: 0x40, sehCount: 0x44, guardCheck: 0x48,
	cfTable: 0x50, cfCount: 0x54, guardFlags: 0x58, dynamicReloc: 0x78,
	ehTable: 0xA4, ehCount: 0xA8, hotPatch: 0x94, ptr: 4,
}

var peLC64 = peLCLayout{
	cookie: 0x58, sehTable: 0x60, sehCount: 0x68, guardCheck: 0x70,
	cfTable: 0x80, cfCount: 0x88, guardFlags: 0x90, dynamicReloc: 0xC0,
	ehTable: 0x108, ehCount: 0x110, hotPatch: 0xF0, ptr: 8,
}

// GuardFlags bits, in ascending order so the reported list is stable.
var peGuardFlags = []struct {
	bit  uint32
	name string
}{
	{0x00000100, "CF_INSTRUMENTED"},
	{0x00000200, "CFW_INSTRUMENTED"},
	{0x00000400, "CF_FUNCTION_TABLE_PRESENT"},
	{0x00000800, "SECURITY_COOKIE_UNUSED"},
	{0x00001000, "PROTECT_DELAYLOAD_IAT"},
	{0x00002000, "DELAYLOAD_IAT_IN_ITS_OWN_SECTION"},
	{0x00004000, "CF_EXPORT_SUPPRESSION_INFO_PRESENT"},
	{0x00008000, "CF_ENABLE_EXPORT_SUPPRESSION"},
	{0x00010000, "CF_LONGJUMP_TABLE_PRESENT"},
	{0x00100000, "RETPOLINE_PRESENT"},
	{0x00200000, "EH_CONTINUATION_TABLE_PRESENT"},
	{0x00400000, "XFG_ENABLED"},
	{0x00800000, "CASTGUARD_PRESENT"},
	{0x01000000, "MEMCPY_PRESENT"},
}

func init() {
	registerOp(op{
		name:  "inspect_pe_load_config",
		route: "L",
		needs: true,
		desc:  "PE load config directory: GS cookie, SafeSEH table, CFG guard flags and the function table addresses",
		run: func(path string) (any, error) {
			b, err := opRead(path, opMaxFile)
			if err != nil {
				return nil, err
			}
			p, err := openPEBytes(b)
			if err != nil {
				return nil, fmt.Errorf("%s: %v", path, err)
			}
			rva, size, err := p.dir(peDirLoadConfig)
			if err != nil {
				return nil, fmt.Errorf("%s: %v", path, err)
			}
			if rva == 0 || size == 0 {
				return struct {
					Present        bool     `json:"present"`
					DeclaredSize   uint32   `json:"declared_size"`
					Truncated      bool     `json:"truncated"`
					Timestamp      uint32   `json:"timestamp"`
					SecurityCookie uint64   `json:"security_cookie"`
					GS             bool     `json:"gs"`
					SafeSEH        bool     `json:"safe_seh"`
					CFG            bool     `json:"cfg"`
					GuardFlags     uint32   `json:"guard_flags"`
					GuardFlagNames []string `json:"guard_flag_names"`
				}{false, 0, false, 0, 0, false, false, false, 0, []string{}}, nil
			}
			lc, err := p.at(rva, size)
			if err != nil {
				return nil, fmt.Errorf("%s load config: %v", path, err)
			}
			if size < 4 {
				return nil, fmt.Errorf("%s load config directory holds %d bytes, too small for the size field", path, size)
			}
			declared := u32le(lc, 0)
			if declared < 4 {
				return nil, fmt.Errorf("%s load config declares %d bytes", path, declared)
			}
			lay := peLC32
			if p.pe32plus {
				lay = peLC64
			}
			// Some real linkers (MSVC before the GuardEH fields existed) write a
			// Size field larger than the directory entry, or a directory larger
			// than the structure version. Read only the bytes both agree on and
			// report the truncation instead of refusing the file: the fields that
			// are present are still valid.
			avail := lc
			truncated := false
			if int(declared) < len(avail) {
				avail = avail[:declared]
			} else if int(declared) > len(avail) {
				truncated = true
			}
			r16 := func(off int) uint16 {
				if off < 0 || off+2 > len(avail) {
					return 0
				}
				return u16le(avail, off)
			}
			r32 := func(off int) uint32 {
				if off < 0 || off+4 > len(avail) {
					return 0
				}
				return u32le(avail, off)
			}
			ptr := func(off int) uint64 {
				v, _ := p.word(avail, off)
				return v
			}
			guard := r32(lay.guardFlags)
			var names []string
			for _, f := range peGuardFlags {
				if guard&f.bit != 0 {
					names = append(names, f.name)
				}
			}
			if names == nil {
				names = []string{}
			}
			cookie := ptr(lay.cookie)
			return struct {
				Present                bool     `json:"present"`
				DeclaredSize           uint32   `json:"declared_size"`
				Truncated              bool     `json:"truncated"`
				Timestamp              uint32   `json:"timestamp"`
				GlobalFlagsClear       uint16   `json:"global_flags_clear"`
				GlobalFlagsSet         uint16   `json:"global_flags_set"`
				CriticalSectionTimeout uint32   `json:"critical_section_timeout"`
				SecurityCookie         uint64   `json:"security_cookie"`
				GS                     bool     `json:"gs"`
				SafeSEH                bool     `json:"safe_seh"`
				SEHTable               uint64   `json:"seh_table"`
				SEHCount               uint64   `json:"seh_count"`
				CFG                    bool     `json:"cfg"`
				CFFunctionTable        uint64   `json:"cfg_function_table"`
				CFFunctionCount        uint64   `json:"cfg_function_count"`
				GuardFlags             uint32   `json:"guard_flags"`
				GuardFlagNames         []string `json:"guard_flag_names"`
				CastGuard              bool     `json:"cast_guard"`
				GuardCheckFunction     uint64   `json:"guard_check_function"`
				DynamicValueRelocTable uint64   `json:"dynamic_value_reloc_table"`
				EHTable                uint64   `json:"exception_table"`
				EHCount                uint64   `json:"exception_count"`
				HotPatchTableOffset    uint32   `json:"hotpatch_table_offset"`
			}{
				Present: true, DeclaredSize: declared, Truncated: truncated, Timestamp: r32(4),
				GlobalFlagsClear: r16(0x0C), GlobalFlagsSet: r16(0x10),
				CriticalSectionTimeout: r32(0x14),
				SecurityCookie:         cookie,
				GS:                     cookie != 0,
				SafeSEH:                ptr(lay.sehTable) != 0 && ptr(lay.sehCount) != 0,
				SEHTable:               ptr(lay.sehTable), SEHCount: ptr(lay.sehCount),
				CFG:             guard&0x100 != 0 || ptr(lay.cfTable) != 0,
				CFFunctionTable: ptr(lay.cfTable), CFFunctionCount: ptr(lay.cfCount),
				GuardFlags:             guard,
				GuardFlagNames:         names,
				CastGuard:              guard&0x800000 != 0,
				GuardCheckFunction:     ptr(lay.guardCheck),
				DynamicValueRelocTable: ptr(lay.dynamicReloc),
				EHTable:                ptr(lay.ehTable), EHCount: ptr(lay.ehCount),
				HotPatchTableOffset: r32(lay.hotPatch),
			}, nil
		},
	})
}
