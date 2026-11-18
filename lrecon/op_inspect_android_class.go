package main

import (
	"fmt"
	"os"
	"strings"
)

func init() {
	registerOp(op{
		name:  "inspect_android_class",
		route: "L",
		needs: true,
		desc:  "resolve one DEX class_def (class → type_ids → string_ids): superclass, interfaces, source file, member counts",
		run: func(path string) (any, error) {
			file, sel := opSelectorLoose(path)
			if sel == "" {
				return nil, fmt.Errorf("this op needs <apk-or-dex>#<com.example.Class>")
			}
			b, err := dexReadBytes(file)
			if err != nil {
				return nil, err
			}
			var d Digest
			r, err := dexOpen(b, &d)
			if err != nil {
				return nil, err
			}
			i, err := dexClassIndex(r, sel)
			if err != nil {
				// A selector the caller typed is bad_arg, not a tool fault.
				return nil, fmt.Errorf("%s: %q is not a class in the dex", file, sel)
			}
			def := r.clsOff + i*32
			class, _ := dexTypeName(r, u32le(b, def))
			super, _ := dexTypeName(r, u32le(b, def+8))
			source, _ := r.str(u32le(b, def+16))
			var ifaces []string
			if off := int(u32le(b, def+12)); off != 0 && dexIn(len(b), off, 4, 1) {
				n := int(u32le(b, off))
				for k := 0; k < n && k < 64; k++ {
					at := off + 4 + 2*k
					if !dexIn(len(b), at, 2, 1) {
						break
					}
					if name, ok := dexTypeName(r, uint32(u16le(b, at))); ok {
						ifaces = append(ifaces, name)
					}
				}
			}
			dataOff := int(u32le(b, def+24))
			var fields, methods []dexEntry
			if dataOff != 0 { // 0 = the class has no code, so there is no class_data to parse
				var derr error
				fields, methods, derr = dexClassData(r, dataOff)
				if derr != nil {
					return nil, fmt.Errorf("%s: %w", file, derr)
				}
			}
			return struct {
				Class      string   `json:"class"`
				Superclass string   `json:"superclass,omitempty"`
				Source     string   `json:"source_file,omitempty"`
				Access     uint32   `json:"access_flags"`
				Interfaces []string `json:"interfaces,omitempty"`
				Fields     int      `json:"fields"`
				Methods    int      `json:"methods"`
				MethodList []string `json:"method_names,omitempty"`
			}{Class: strings.TrimSuffix(strings.TrimPrefix(class, "L"), ";"), Superclass: super,
				Source: source, Access: u32le(b, def+4), Interfaces: ifaces,
				Fields: len(fields), Methods: len(methods), MethodList: dexMethodNames(r, methods, 40)}, nil
		},
	})
}

// dexMethodNames resolves up to max method names from a member list.
func dexMethodNames(r dexReader, list []dexEntry, max int) []string {
	var out []string
	for _, e := range list {
		if len(out) >= max {
			break
		}
		if name, ok := r.methodName(e.Idx); ok {
			out = append(out, name)
		}
	}
	return out
}

// opSelectorLoose is opSelector for the DEX ops: a "<file>#<class>" call whose
// file is missing has to answer io, not the missing-selector needs_arg.
// opSelector splits only when the file part exists, so a missing file loses the
// caller's selector; the documented form is honoured here instead. An existing
// path is still never split, so a "#" inside a real file name stays part of it.
func opSelectorLoose(path string) (file, sel string) {
	if file, sel = opSelector(path); sel != "" {
		return file, sel
	}
	if _, err := os.Stat(path); err == nil {
		return path, ""
	}
	if i := strings.LastIndexByte(path, '#'); i > 0 && i+1 < len(path) {
		return path[:i], path[i+1:]
	}
	return path, ""
}
