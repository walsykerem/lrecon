package main

import (
	"fmt"
	"strings"
)

func init() {
	registerOp(op{
		name:  "inspect_android_method",
		route: "L",
		needs: true,
		desc:  "walk one class_data_item ULEB chain: per-method idx, access flags and code_off",
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
				// The selector is the caller's, so a miss is bad_arg, not a
				// tool fault: a member name after the class is the usual cause.
				msg := fmt.Sprintf("%s: %q is not a class in the dex", file, sel)
				if k := strings.LastIndexByte(sel, '.'); k >= 0 && k+1 < len(sel) {
					if c := sel[k+1]; c >= 'a' && c <= 'z' {
						msg += " (this op lists one class's methods; drop the member name after the class)"
					}
				}
				return nil, fmt.Errorf("%s", msg)
			}
			def := r.clsOff + i*32
			class, _ := dexTypeName(r, u32le(b, def))
			dataOff := int(u32le(b, def+24))
			if dataOff == 0 {
				return skipf("class %s has no class_data (no code)", strings.TrimSuffix(strings.TrimPrefix(class, "L"), ";")), nil
			}
			_, methods, err := dexClassData(r, dataOff)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", file, err)
			}
			type row struct {
				Name    string `json:"name"`
				Flags   string `json:"access,omitempty"`
				CodeOff int    `json:"code_off"`
			}
			res := struct {
				Class   string `json:"class"`
				Methods int    `json:"methods"`
				Rows    []row  `json:"rows,omitempty"`
			}{Class: strings.TrimSuffix(strings.TrimPrefix(class, "L"), ";"), Methods: len(methods)}
			for _, e := range methods {
				if len(res.Rows) >= 60 {
					break
				}
				name, ok := r.methodName(e.Idx)
				if !ok {
					continue
				}
				res.Rows = append(res.Rows, row{Name: name, Flags: dexMethodFlag(e.Access), CodeOff: e.CodeOff})
			}
			return res, nil
		},
	})
}
