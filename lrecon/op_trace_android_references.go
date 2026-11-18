package main

// final.md 154 (item 42): trace_android_references.
//
// Call edges are decoded, not guessed: class_defs point at class_data_item, its
// ULEB chain names each method's code_item, and the code_item's invoke-kind
// instructions carry the method_ids index that is the callee. One pass over the
// dex builds both directions, so a query gets its callers and callees.

import (
	"fmt"
	"sort"
)

// maxRefEdges bounds one direction of the edge table; a hot method such as a
// logging helper has more callers than a reader can use.
const maxRefEdges = 200

func init() {
	registerOp(op{
		name:  "trace_android_references",
		route: "L",
		needs: true,
		desc:  "decode DEX class_data_item + code_item invoke instructions into call edges, then report the edges a LRECON_QUERY class or method appears in",
		run: func(path string) (any, error) {
			query, err := nativeEnvHint("LRECON_QUERY", "a class or method name to trace, e.g. com.example.Foo or okhttp3/RealCall")
			if err != nil {
				return nil, err
			}
			abs, err := absTarget(path)
			if err != nil {
				return nil, err
			}
			b, err := dexReadBytes(abs)
			if err != nil {
				return nil, err
			}
			r, err := dexOpen(b, &Digest{})
			if err != nil {
				return nil, err
			}

			type edge struct {
				From string `json:"from"`
				To   string `json:"to"`
			}
			res := struct {
				Query     string   `json:"query"`
				Classes   int      `json:"class_defs"`
				Methods   int      `json:"methods_with_code"`
				CodeItems int      `json:"code_items"`
				Edges     int      `json:"edges"`
				Nodes     []string `json:"nodes"`
				Callers   []edge   `json:"callers"`
				Callees   []edge   `json:"callees"`
				Truncated bool     `json:"truncated"`
			}{Query: query}

			n := int(u32le(r.b, 0x60))
			if n == 0 {
				return nil, fmt.Errorf("%s has no class_defs, so it carries no call edges", abs)
			}
			res.Classes = n
			edges := 0
			for i := range n {
				at := r.clsOff + 32*i
				if !dexIn(r.end, at, 32, 1) {
					return nil, fmt.Errorf("%s: class_def %d at %#x is not inside the %d-byte dex", abs, i, at, r.end)
				}
				owner, ok := r.typeName(u32le(r.b, at))
				if !ok {
					return nil, fmt.Errorf("%s: class_def %d type unreadable: it is not in type_ids", abs, i)
				}
				dataOff := int(u32le(r.b, at+24))
				if dataOff == 0 {
					// A class with no class_data_item (every marker interface,
					// and any class the shrinker left empty) carries no method
					// and no code_item. Reading offset 0 would decode the dex
					// header as a ULEB chain and turn a normal dex into a
					// refusal, so it is skipped instead.
					continue
				}
				_, methods, err := dexClassData(r, dataOff)
				if err != nil {
					return nil, fmt.Errorf("%s: class_def %d (%s): %v", abs, i, owner, err)
				}
				for _, m := range methods {
					if m.CodeOff == 0 {
						continue
					}
					res.Methods++
					name, ok := r.methodName(m.Idx)
					if !ok {
						return nil, fmt.Errorf("%s: class_def %d method_id %d unreadable: it is not in method_ids", abs, i, m.Idx)
					}
					caller := owner + "->" + name
					targets, err := metaBInvokes(r, m.CodeOff)
					if err != nil {
						return nil, fmt.Errorf("%s: %s: %v", abs, caller, err)
					}
					res.CodeItems++
					for _, t := range targets {
						callee, ok := metaBMethodLabel(r, t)
						if !ok {
							return nil, fmt.Errorf("%s: %s invokes method_id %d, which is not in method_ids", abs, caller, t)
						}
						edges++
						if metaBQuery(caller, query) {
							if len(res.Callees) < maxRefEdges {
								res.Callees = append(res.Callees, edge{caller, callee})
							} else {
								res.Truncated = true
							}
						}
						if metaBQuery(callee, query) {
							if len(res.Callers) < maxRefEdges {
								res.Callers = append(res.Callers, edge{caller, callee})
							} else {
								res.Truncated = true
							}
						}
					}
				}
			}
			res.Edges = edges
			nodes := map[string]bool{}
			for _, e := range res.Callees {
				nodes[e.To] = true
			}
			for _, e := range res.Callers {
				nodes[e.From] = true
			}
			for _, e := range append(append([]edge{}, res.Callers...), res.Callees...) {
				if metaBQuery(e.From, query) {
					nodes[e.From] = true
				}
				if metaBQuery(e.To, query) {
					nodes[e.To] = true
				}
			}
			for k := range nodes {
				res.Nodes = append(res.Nodes, k)
			}
			sort.Strings(res.Nodes)
			if res.Edges == 0 {
				return skipf("%s: %d class_defs carry no method with an invokable code_item", abs, n), nil
			}
			if len(res.Nodes) == 0 {
				return skipf("%s: %d call edges decoded, none touching %q", abs, res.Edges, query), nil
			}
			return res, nil
		},
	})
}
