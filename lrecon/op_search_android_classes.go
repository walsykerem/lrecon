package main

// final.md 153 (item 41): search_android_classes.
//
// The DEX string_ids and type_ids tables are the class index: every class a
// build ships is a descriptor string there, whether or not it has a class_def.
// A query from LRECON_QUERY is answered from both tables, then joined to
// class_defs for access flags, superclass and member counts.

import (
	"errors"
	"fmt"
	"sort"
)

func init() {
	registerOp(op{
		name:  "search_android_classes",
		route: "L",
		needs: true,
		desc:  "index the DEX string_ids/type_ids tables for class descriptors matching LRECON_QUERY and join them to class_defs",
		run: func(path string) (any, error) {
			query, err := nativeEnvHint("LRECON_QUERY", "a class name or descriptor substring, e.g. com.example or Lretrofit2/")
			if err != nil {
				return nil, err
			}
			abs, err := absTarget(path)
			if err != nil {
				return nil, err
			}

			type strHit struct {
				Index uint32 `json:"string_idx"`
				Value string `json:"value"`
			}
			type classHit struct {
				Descriptor string `json:"descriptor"`
				TypeIdx    uint32 `json:"type_idx"`
				Access     uint32 `json:"access,omitempty"`
				Super      string `json:"super,omitempty"`
				Classes    int    `json:"class_defs"`
				Methods    int    `json:"methods"`
				Fields     int    `json:"fields"`
			}
			res := struct {
				Query   string `json:"query"`
				Strings int    `json:"string_ids"`
				Types   int    `json:"type_ids"`
				Matches int    `json:"class_matches"`
				// The lists stop at 50 rows; the totals keep a capped list from
				// reading as the whole index (same shape as list_strings).
				MatchesTotal int        `json:"class_matches_total"`
				StringsTotal int        `json:"string_matches_total"`
				Truncated    bool       `json:"truncated"`
				Hits         []strHit   `json:"string_hits"`
				Classes      []classHit `json:"classes"`
				Note         string     `json:"note,omitempty"`
			}{Query: query}

			b, err := dexReadBytes(abs)
			if err != nil {
				var nd noDexError
				if !errors.As(err, &nd) {
					return nil, err
				}
				// A target with no DEX has no matching classes: an empty result
				// with the reason, not a bad_arg that ends a sweep on its first
				// non-Android binary.
				res.Note = nd.msg
				return res, nil
			}
			d := &Digest{}
			r, err := dexOpen(b, d)
			if err != nil {
				return nil, err
			}
			res.Strings, res.Types = r.strSize, r.typSize

			for i := 0; i < r.strSize; i++ {
				s, ok := r.str(uint32(i))
				if !ok {
					return nil, fmt.Errorf("%s: string_id %d is not readable", abs, i)
				}
				if metaBQuery(s, query) {
					res.StringsTotal++
					if len(res.Hits) < 50 {
						res.Hits = append(res.Hits, strHit{Index: uint32(i), Value: s})
					}
				}
			}

			// class_defs indexed by their class type, so a type hit carries its def.
			n := int(u32le(r.b, 0x60))
			defs := map[uint32]int{}
			for i := range n {
				at := r.clsOff + 32*i
				if !dexIn(r.end, at, 32, 1) {
					return nil, fmt.Errorf("%s: class_def %d at %#x is not inside the dex", abs, i, at)
				}
				defs[u32le(r.b, at)] = i
			}
			for t := 0; t < r.typSize; t++ {
				desc, ok := r.typeName(uint32(t))
				if !ok {
					return nil, fmt.Errorf("%s: type_id %d descriptor is not readable", abs, t)
				}
				if !metaBQuery(desc, query) {
					continue
				}
				res.MatchesTotal++
				if len(res.Classes) >= 50 {
					continue
				}
				h := classHit{Descriptor: desc, TypeIdx: uint32(t)}
				if di, ok := defs[uint32(t)]; ok {
					at := r.clsOff + 32*di
					h.Classes = 1
					h.Access = u32le(r.b, at+4)
					if s := u32le(r.b, at+8); s != dexNoIndex {
						if sup, ok := r.typeName(s); ok {
							h.Super = sup
						}
					}
					fields, methods, err := dexClassData(r, int(u32le(r.b, at+24)))
					if err != nil {
						return nil, fmt.Errorf("%s: class_def %d (%s): %v", abs, di, desc, err)
					}
					h.Fields, h.Methods = len(fields), len(methods)
				}
				res.Classes = append(res.Classes, h)
			}
			res.Matches = len(res.Classes)
			res.Truncated = res.MatchesTotal > len(res.Classes) || res.StringsTotal > len(res.Hits)
			sort.Slice(res.Classes, func(i, j int) bool { return res.Classes[i].Descriptor < res.Classes[j].Descriptor })
			if res.MatchesTotal == 0 && res.StringsTotal == 0 {
				return skipf("%s has no string or type matching %q among %d strings / %d types", abs, query, r.strSize, r.typSize), nil
			}
			return res, nil
		},
	})
}
