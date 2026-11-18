package main

// final.md 156 (item 44): verify_managed_native_boundaries.
//
// Every ImplMap row is a promise that the managed method is a thunk into one
// named native import. This op reads the MethodDef body, requires the
// "ff 25 <disp32>" indirect jump, decodes the slot it jumps through, and only
// reports verified when that slot is the import the ImplMap names.

import (
	"bytes"
	"fmt"
	"path"
	"strings"
)

func init() {
	registerOp(op{
		name:  "verify_managed_native_boundaries",
		route: "L",
		needs: true,
		desc:  "per ImplMap row: read the MethodDef RVA, check the `jmp [IAT]` thunk and match the slot against the PE import it names",
		run: func(path string) (any, error) {
			c, err := openCLIView(path)
			if err != nil {
				return nil, err
			}
			if c.n(0x1C) == 0 {
				return skipf("%s has no ImplMap rows, so it declares no P/Invoke boundary", path), nil
			}
			b, err := opRead(path, opMaxFile)
			if err != nil {
				return nil, err
			}
			base, ptr, ok := metaBPEBase(b)
			if !ok {
				return nil, fmt.Errorf("%s: PE optional header unreadable", path)
			}
			img, ok := openPEImage(bytes.NewReader(b))
			if !ok {
				return nil, fmt.Errorf("%s: PE sections unreadable", path)
			}
			imports, impErr := peImports(path)

			imW, imO := c.cols(0x1C)
			mrW, mrO := c.cols(0x1A)
			mdW, mdO := c.cols(0x06)
			tdW, tdO := c.cols(0x02)

			type boundary struct {
				Managed   string `json:"managed"`
				Native    string `json:"native"`
				Module    string `json:"module"`
				CallConv  string `json:"call_conv"`
				MethodRVA uint32 `json:"method_rva"`
				Thunk     string `json:"thunk"`
				Slot      uint64 `json:"iat_slot,omitempty"`
				Verified  bool   `json:"verified"`
				Note      string `json:"note,omitempty"`
			}
			res := struct {
				Boundaries int `json:"boundaries"`
				// The rows stop at 100; the total keeps the cap from reading as
				// the whole table (same shape as list_strings).
				BoundariesTotal int        `json:"boundaries_total"`
				Truncated       bool       `json:"truncated"`
				Verified        int        `json:"verified"`
				Imports         int        `json:"pe_imports"`
				Note            string     `json:"note,omitempty"`
				Rows            []boundary `json:"rows"`
			}{Imports: len(imports)}
			if impErr != nil {
				res.Note = "PE import table: " + impErr.Error()
			}
			add := func(b boundary) {
				res.BoundariesTotal++
				if len(res.Rows) < 100 {
					res.Rows = append(res.Rows, b)
				}
			}

			for i := 0; i < c.n(0x1C); i++ {
				row := c.row(0x1C, i)
				flags := u16le(row, imO[0])
				native := c.str(idxAt(row, imO[2], imW[2]))
				module := ""
				if mi := int(idxAt(row, imO[3], imW[3])); mi > 0 && mi <= c.n(0x1A) {
					module = c.str(idxAt(c.row(0x1A, mi-1), mrO[0], mrW[0]))
				}
				member := idxAt(row, imO[1], imW[1])
				if member&1 == 0 {
					// MemberForwarded tag 0 is Field: a marshalled field, not a call thunk.
					continue
				}
				ref := int(member >> 1)
				if ref <= 0 || ref > c.n(0x06) {
					return nil, fmt.Errorf("%s ImplMap %d forwards to MethodDef %d, table holds %d", path, i, ref, c.n(0x06))
				}
				managed := c.str(idxAt(c.row(0x06, ref-1), mdO[3], mdW[3]))
				if owner := typeOwner(c, ref, tdW, tdO); owner != "" {
					managed = owner + "::" + managed
				}
				rva := u32le(c.row(0x06, ref-1), mdO[0])
				if rva == 0 {
					// .NET Core resolves P/Invokes at JIT time: no IL stub exists to check.
					add(boundary{Managed: managed, Native: native, Module: module,
						CallConv: pinvokeCallConv(flags),
						Note:     "MethodDef RVA 0: no IL body, so there is no `jmp [IAT]` thunk to verify"})
					continue
				}
				e := boundary{Managed: managed, Native: native, Module: module,
					CallConv: pinvokeCallConv(flags), MethodRVA: rva}
				slot, note, verr := metaBThunk(img, rva, base, ptr)
				if verr != nil {
					return nil, fmt.Errorf("%s ImplMap %d: %v", path, i, verr)
				}
				e.Thunk, e.Note = slot.bytes, note
				e.Slot = slot.va
				if e.Slot == 0 {
					add(e)
					continue
				}
				hit, ok := metaBImportAt(imports, e.Slot)
				if !ok {
					e.Note = joinNote(e.Note, "slot is not in the PE import table")
					add(e)
					continue
				}
				if !sameModule(module, hit.Library) {
					e.Note = joinNote(e.Note, fmt.Sprintf("slot imports %s from %s", hit.Name, hit.Library))
					add(e)
					continue
				}
				if !sameImport(native, hit.Name) {
					e.Note = joinNote(e.Note, fmt.Sprintf("slot imports %s, not %s", hit.Name, native))
					add(e)
					continue
				}
				e.Verified = true
				add(e)
			}
			res.Boundaries = len(res.Rows)
			res.Truncated = res.BoundariesTotal > res.Boundaries
			for _, r := range res.Rows {
				if r.Verified {
					res.Verified++
				}
			}
			if res.BoundariesTotal == 0 {
				return nil, fmt.Errorf("%s ImplMap rows forward to fields only; no P/Invoke call boundary to verify", path)
			}
			return res, nil
		},
	})
}

type metaBSlot struct {
	bytes string
	va    uint64 // IAT slot address the thunk jumps through, 0 when unknown
}

// metaBThunk reads the method body at rva and decodes the one instruction a
// P/Invoke stub holds. A stub that is not `jmp [slot]` is reported with the
// bytes it does hold; only unreadable bytes are an error.
func metaBThunk(img peImage, rva uint32, base uint64, ptr int) (metaBSlot, string, error) {
	head, ok := img.at(rva, 1)
	if !ok {
		return metaBSlot{}, "", fmt.Errorf("method RVA %#x is outside every section", rva)
	}
	code := rva
	note := ""
	switch head[0] & 3 {
	case 2: // tiny header: one byte, code follows
		code = rva + 1
	case 3: // fat header: size in 4-byte dwords
		hdr, ok := img.at(rva, 12)
		if !ok {
			return metaBSlot{}, "", fmt.Errorf("fat method header at %#x truncated", rva)
		}
		n := (u16le(hdr, 0) >> 12) * 4
		if n < 12 {
			return metaBSlot{}, "", fmt.Errorf("fat method header at %#x declares %d bytes", rva, n)
		}
		code = rva + uint32(n)
	default:
		return metaBSlot{}, "", fmt.Errorf("method RVA %#x is not an ECMA-335 method body header (byte %#x)", rva, head[0])
	}
	body, ok := img.at(code, 6)
	if !ok {
		return metaBSlot{}, "", fmt.Errorf("thunk at RVA %#x truncated", code)
	}
	t := metaBSlot{bytes: fmt.Sprintf("% x", body)}
	if body[0] != 0xFF || body[1] != 0x25 {
		return t, "body does not start with `jmp [slot]` (ff 25)", nil
	}
	disp := int64(int32(u32le(body, 2)))
	if ptr == 8 {
		t.va = base + uint64(int64(code)+6+disp)
	} else {
		t.va = uint64(uint32(int32(disp))) // PE32 thunks hold the slot's absolute VA
	}
	return t, note, nil
}

func metaBImportAt(imports []nativeAPI, va uint64) (nativeAPI, bool) {
	for _, imp := range imports {
		if imp.Stub == va {
			return imp, true
		}
	}
	return nativeAPI{}, false
}

func pinvokeCallConv(flags uint16) string {
	names := map[uint16]string{1: "cdecl", 2: "stdcall", 3: "thiscall", 4: "fastcall", 5: "winapi"}
	switch cc := (flags >> 8) & 7; cc {
	case 0:
		return "winapi" // absent field means the platform default
	default:
		if n, ok := names[cc]; ok {
			return n
		}
		return fmt.Sprintf("cc%d", cc)
	}
}

func sameModule(module, library string) bool {
	strip := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		return strings.TrimSuffix(s, ".dll")
	}
	return strip(module) == strip(path.Base(strip(library)))
}

// sameImport compares an ImplMap entry point with an import name. Win32 name
// decoration is not part of either identity, so "_MessageBoxA@16" matches
// "MessageBoxA".
func sameImport(native, imported string) bool {
	norm := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimPrefix(s, "_")
		if i := strings.IndexByte(s, '@'); i > 0 {
			s = s[:i]
		}
		return s
	}
	return norm(native) == norm(imported)
}

func joinNote(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}
