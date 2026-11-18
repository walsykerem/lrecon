package main

import "fmt"

// WebAssembly artifact: the section directory plus the import and export
// tables. Everything in a wasm module is LEB128, so one cursor walks the
// payloads; the section size is checked before a payload is touched.

var wasmSectionNames = map[uint8]string{
	0: "custom", 1: "type", 2: "import", 3: "function", 4: "table", 5: "memory",
	6: "global", 7: "export", 8: "start", 9: "element", 10: "code", 11: "data",
	12: "datacount",
}

var wasmKindNames = map[uint8]string{0: "func", 1: "table", 2: "memory", 3: "global", 4: "tag"}

type wasmArtifactSection struct {
	ID      uint8  `json:"id"`
	Name    string `json:"name"`
	Offset  int    `json:"payload_offset"`
	Size    uint32 `json:"payload_bytes"`
	Entries uint32 `json:"entries,omitempty"`
}

type wasmArtifactImport struct {
	Module string    `json:"module"`
	Field  string    `json:"field"`
	Kind   string    `json:"kind"`
	Type   uint32    `json:"type_index,omitempty"`
	Limits *wsLimits `json:"limits,omitempty"`
}

type wasmArtifactExport struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Index uint32 `json:"index"`
}

type wsLimits struct {
	Min  uint32 `json:"min"`
	Max  uint32 `json:"max,omitempty"`
	Flag uint32 `json:"flag"`
}

type wsCursor struct {
	b []byte
	i int
}

func (c *wsCursor) u8() (uint8, bool) {
	if c.i >= len(c.b) {
		return 0, false
	}
	v := c.b[c.i]
	c.i++
	return v, true
}

func (c *wsCursor) u32() (uint32, bool) {
	var v uint32
	for n := range 5 {
		b, ok := c.u8()
		if !ok {
			return 0, false
		}
		if n == 4 && b&0xf0 != 0 {
			return 0, false
		}
		v |= uint32(b&0x7f) << (7 * n)
		if b&0x80 == 0 {
			return v, true
		}
	}
	return 0, false
}

func (c *wsCursor) name() (string, bool) {
	n, ok := c.u32()
	if !ok || uint64(n) > uint64(len(c.b)-c.i) {
		return "", false
	}
	s := string(c.b[c.i : c.i+int(n)])
	c.i += int(n)
	return s, true
}

func (c *wsCursor) limits() (wsLimits, bool) {
	flag, ok := c.u32()
	if !ok {
		return wsLimits{}, false
	}
	min, ok := c.u32()
	if !ok {
		return wsLimits{}, false
	}
	l := wsLimits{Min: min, Flag: flag}
	if flag&1 != 0 {
		if l.Max, ok = c.u32(); !ok {
			return wsLimits{}, false
		}
	}
	return l, true
}

func init() {
	registerOp(op{
		name:  "inspect_wasm_artifact",
		route: "L",
		needs: true,
		desc:  "WebAssembly module: magic and version, every section with its payload offset and size, and the import and export tables",
		run: func(path string) (any, error) {
			b, err := opRead(path, opMaxFile)
			if err != nil {
				return nil, err
			}
			if len(b) < 8 || string(b[:4]) != "\x00asm" {
				return nil, fmt.Errorf("%s has no wasm magic", path)
			}
			version := u32le(b, 4)
			if version != wasmVersion {
				return nil, fmt.Errorf("%s is wasm version %#x; only the MVP (%d) section grammar is decoded", path, version, wasmVersion)
			}
			res := struct {
				Magic    string                `json:"magic"`
				Version  uint32                `json:"version"`
				Sections []wasmArtifactSection `json:"sections"`
				Imports  []wasmArtifactImport  `json:"imports,omitempty"`
				Exports  []wasmArtifactExport  `json:"exports,omitempty"`
			}{Magic: `\0asm`, Version: version}
			for at := 8; at < len(b); {
				id := b[at]
				c := &wsCursor{b: b, i: at + 1}
				size, ok := c.u32()
				if !ok {
					return nil, fmt.Errorf("%s: section size at %d is not a LEB128 u32", path, at)
				}
				start := c.i
				if uint64(start)+uint64(size) > uint64(len(b)) {
					return nil, fmt.Errorf("%s: section %d at %d declares %d bytes, file holds %d", path, id, at, size, len(b)-start)
				}
				payload := b[start : start+int(size)]
				sec := wasmArtifactSection{ID: id, Name: wasmSectionNames[id], Offset: start, Size: size}
				if sec.Name == "" {
					sec.Name = fmt.Sprintf("unknown-%d", id)
				}
				s := &wsCursor{b: payload}
				switch id {
				case 0:
					name, ok := s.name()
					if !ok {
						return nil, fmt.Errorf("%s: custom section at %d has a cut name", path, at)
					}
					sec.Name = "custom:" + name
				case 1:
					if sec.Entries, ok = s.u32(); !ok {
						return nil, fmt.Errorf("%s: type section at %d has no count", path, at)
					}
				case 2:
					n, ok := s.u32()
					if !ok {
						return nil, fmt.Errorf("%s: import section at %d has no count", path, at)
					}
					sec.Entries = n
					for i := range n {
						imp, ierr := readWasmImport(s)
						if ierr != nil {
							return nil, fmt.Errorf("%s: import %d at section %d: %v", path, i, at, ierr)
						}
						res.Imports = append(res.Imports, imp)
					}
					if s.i != len(s.b) {
						return nil, fmt.Errorf("%s: import section at %d has %d trailing bytes", path, at, len(s.b)-s.i)
					}
				case 3, 4, 5, 6:
					if sec.Entries, ok = s.u32(); !ok {
						return nil, fmt.Errorf("%s: section %d at %d has no count", path, id, at)
					}
				case 7:
					n, ok := s.u32()
					if !ok {
						return nil, fmt.Errorf("%s: export section at %d has no count", path, at)
					}
					sec.Entries = n
					for i := range n {
						name, ok := s.name()
						if !ok {
							return nil, fmt.Errorf("%s: export %d at section %d has a cut name", path, i, at)
						}
						kind, ok := s.u8()
						if !ok {
							return nil, fmt.Errorf("%s: export %q has no kind", path, name)
						}
						idx, ok := s.u32()
						if !ok {
							return nil, fmt.Errorf("%s: export %q has no index", path, name)
						}
						k, known := wasmKindNames[kind]
						if !known {
							return nil, fmt.Errorf("%s: export %q has kind %d", path, name, kind)
						}
						res.Exports = append(res.Exports, wasmArtifactExport{Name: name, Kind: k, Index: idx})
					}
					if s.i != len(s.b) {
						return nil, fmt.Errorf("%s: export section at %d has %d trailing bytes", path, at, len(s.b)-s.i)
					}
				}
				res.Sections = append(res.Sections, sec)
				at = start + int(size)
			}
			if len(res.Sections) == 0 {
				return nil, fmt.Errorf("%s has an empty section table", path)
			}
			return res, nil
		},
	})
}

// readWasmImport consumes one import entry including its descriptor.
func readWasmImport(c *wsCursor) (wasmArtifactImport, error) {
	var imp wasmArtifactImport
	var ok bool
	if imp.Module, ok = c.name(); !ok {
		return imp, fmt.Errorf("module name is cut")
	}
	if imp.Field, ok = c.name(); !ok {
		return imp, fmt.Errorf("field name is cut")
	}
	kind, ok := c.u8()
	if !ok {
		return imp, fmt.Errorf("kind is cut")
	}
	name, known := wasmKindNames[kind]
	if !known {
		return imp, fmt.Errorf("unknown kind %d", kind)
	}
	imp.Kind = name
	switch kind {
	case 0:
		if imp.Type, ok = c.u32(); !ok {
			return imp, fmt.Errorf("function type index is cut")
		}
	case 1:
		if _, ok = c.u8(); !ok {
			return imp, fmt.Errorf("table element type is cut")
		}
		l, ok := c.limits()
		if !ok {
			return imp, fmt.Errorf("table limits are cut")
		}
		imp.Limits = &l
	case 2:
		l, ok := c.limits()
		if !ok {
			return imp, fmt.Errorf("memory limits are cut")
		}
		imp.Limits = &l
	case 3:
		if _, ok = c.u8(); !ok {
			return imp, fmt.Errorf("global value type is cut")
		}
		if _, ok = c.u8(); !ok {
			return imp, fmt.Errorf("global mutability is cut")
		}
	case 4:
		if _, ok = c.u8(); !ok {
			return imp, fmt.Errorf("tag attribute is cut")
		}
		if imp.Type, ok = c.u32(); !ok {
			return imp, fmt.Errorf("tag type index is cut")
		}
	}
	return imp, nil
}
