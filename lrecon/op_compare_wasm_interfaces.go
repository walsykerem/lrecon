package main

import (
	"fmt"
)

// wasmIface is the import/export surface of one module, as "module.field" and
// export names.
type wasmIface struct {
	imports []string
	exports []string
}

func init() {
	registerOp(op{
		name:  "compare_wasm_interfaces",
		route: "L",
		needs: true,
		desc:  "diff the import/export sections of two wasm modules (<a>,<b>)",
		run: func(path string) (any, error) {
			left, right, err := opPair(path)
			if err != nil {
				return nil, err
			}
			a, err := readWasmIface(left)
			if err != nil {
				return nil, err
			}
			b, err := readWasmIface(right)
			if err != nil {
				return nil, err
			}
			res := struct {
				Left            string   `json:"left"`
				Right           string   `json:"right"`
				LeftImports     int      `json:"left_imports"`
				RightImports    int      `json:"right_imports"`
				LeftExports     int      `json:"left_exports"`
				RightExports    int      `json:"right_exports"`
				ImportsOnlyLeft []string `json:"imports_only_left,omitempty"`
				ImportsOnlyRght []string `json:"imports_only_right,omitempty"`
				ExportsOnlyLeft []string `json:"exports_only_left,omitempty"`
				ExportsOnlyRght []string `json:"exports_only_right,omitempty"`
				// cap50 trims the lists; the totals say how much was trimmed.
				ImportsOnlyLeftTotal  int  `json:"imports_only_left_total"`
				ImportsOnlyRightTotal int  `json:"imports_only_right_total"`
				ExportsOnlyLeftTotal  int  `json:"exports_only_left_total"`
				ExportsOnlyRightTotal int  `json:"exports_only_right_total"`
				Identical             bool `json:"identical"`
			}{Left: left, Right: right,
				LeftImports: len(a.imports), RightImports: len(b.imports),
				LeftExports: len(a.exports), RightExports: len(b.exports)}
			impL := onlyIn(a.imports, b.imports)
			impR := onlyIn(b.imports, a.imports)
			expL := onlyIn(a.exports, b.exports)
			expR := onlyIn(b.exports, a.exports)
			res.ImportsOnlyLeftTotal, res.ImportsOnlyRightTotal = len(impL), len(impR)
			res.ExportsOnlyLeftTotal, res.ExportsOnlyRightTotal = len(expL), len(expR)
			res.Identical = len(impL)+len(impR)+len(expL)+len(expR) == 0
			res.ImportsOnlyLeft = cap50(impL)
			res.ImportsOnlyRght = cap50(impR)
			res.ExportsOnlyLeft = cap50(expL)
			res.ExportsOnlyRght = cap50(expR)
			return res, nil
		},
	})
}

// readWasmIface walks the section list and decodes section 2 (import) and 7
// (export) with the digest's own cursor.
func readWasmIface(path string) (wasmIface, error) {
	b, err := opRead(path, 64<<20)
	if err != nil {
		return wasmIface{}, err
	}
	if len(b) < 8 || string(b[:4]) != "\x00asm" {
		return wasmIface{}, fmt.Errorf("%s is not a wasm module", path)
	}
	var out wasmIface
	s := &wasmCursor{b: b[8:]}
	for {
		id, ok := s.u8()
		if !ok {
			break
		}
		size, ok := s.u32()
		if !ok {
			return out, fmt.Errorf("%s: section %d size is cut", path, id)
		}
		body, ok := s.bytes(size)
		if !ok {
			return out, fmt.Errorf("%s: section %d body is cut", path, id)
		}
		switch id {
		case 2:
			names, err := wasmImportNames(body)
			if err != nil {
				return out, fmt.Errorf("%s: import section: %w", path, err)
			}
			out.imports = append(out.imports, names...)
		case 7:
			names, err := wasmExportNames(body)
			if err != nil {
				return out, fmt.Errorf("%s: export section: %w", path, err)
			}
			out.exports = append(out.exports, names...)
		}
	}
	out.imports = uniqSorted(out.imports)
	out.exports = uniqSorted(out.exports)
	return out, nil
}

func wasmImportNames(body []byte) ([]string, error) {
	c := &wasmCursor{b: body}
	n, ok := c.u32()
	if !ok {
		return nil, fmt.Errorf("count is cut")
	}
	out := make([]string, 0, n)
	for i := range n {
		mod, ok := c.name()
		if !ok {
			return out, fmt.Errorf("entry %d module name is cut", i)
		}
		field, ok := c.name()
		if !ok {
			return out, fmt.Errorf("entry %d field name is cut", i)
		}
		kind, ok := c.u8()
		if !ok {
			return out, fmt.Errorf("entry %d kind is cut", i)
		}
		if !skipWasmKind(c, kind) {
			return out, fmt.Errorf("entry %d desc is cut (kind %d)", i, kind)
		}
		out = append(out, mod+"."+field)
	}
	return out, nil
}

func skipWasmKind(c *wasmCursor, kind byte) bool {
	switch kind {
	case 0:
		_, ok := c.u32()
		return ok
	case 4:
		// tag import: an attribute byte, then the type index (exception
		// handling). Reading one u32 swallowed the attribute and three bytes of
		// the index, so a module with a tag import was refused as cut.
		if _, ok := c.u8(); !ok {
			return false
		}
		_, ok := c.u32()
		return ok
	case 1:
		if _, ok := c.u8(); !ok {
			return false
		}
		return skipWasmLimits(c)
	case 2:
		return skipWasmLimits(c)
	case 3:
		_, ok := c.u8()
		if !ok {
			return false
		}
		_, ok = c.u8()
		return ok
	}
	return false
}

func skipWasmLimits(c *wasmCursor) bool {
	flags, ok := c.u8()
	if !ok {
		return false
	}
	if _, ok := c.u32(); !ok {
		return false
	}
	if flags&1 != 0 {
		_, ok = c.u32()
	}
	return ok
}

func wasmExportNames(body []byte) ([]string, error) {
	c := &wasmCursor{b: body}
	n, ok := c.u32()
	if !ok {
		return nil, fmt.Errorf("count is cut")
	}
	out := make([]string, 0, n)
	for i := range n {
		name, ok := c.name()
		if !ok {
			return out, fmt.Errorf("export %d name is cut", i)
		}
		if _, ok := c.u8(); !ok {
			return out, fmt.Errorf("export %d kind is cut", i)
		}
		if _, ok := c.u32(); !ok {
			return out, fmt.Errorf("export %d index is cut", i)
		}
		out = append(out, name)
	}
	return out, nil
}
