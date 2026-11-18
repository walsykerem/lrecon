package main

import "fmt"

func init() {
	registerOp(op{
		name:  "inspect_managed_members",
		route: "L",
		needs: true,
		desc:  "ECMA-335 metadata member listing: every TypeDef with its Field/MethodDef names",
		run: func(path string) (any, error) {
			c, err := openCLIView(path)
			if err != nil {
				if d, perr := Probe(path); perr == nil && (d.Kind == "pe" || d.Kind == "pe-dotnet") {
					return skipf("%s is not a managed assembly (no ECMA-335 CLI header and metadata root)", path), nil
				}
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			tdW, tdO := c.cols(0x02)
			mdW, mdO := c.cols(0x06)
			types, fields, methods := c.n(0x02), c.n(0x04), c.n(0x06)
			if types == 0 {
				return skipf("%s has no TypeDef rows (not a managed assembly)", path), nil
			}
			// TypeDef rows carry FieldList/MethodList starts; type i owns the
			// rows up to type i+1's start.
			fieldAt := func(i int) int {
				if i >= types {
					return fields
				}
				return int(idxAt(c.row(0x02, i), tdO[4], tdW[4])) - 1
			}
			methodAt := func(i int) int {
				if i >= types {
					return methods
				}
				return int(idxAt(c.row(0x02, i), tdO[5], tdW[5])) - 1
			}
			type row struct {
				Type    string   `json:"type"`
				Fields  int      `json:"fields"`
				Methods int      `json:"methods"`
				Names   []string `json:"method_names,omitempty"`
			}
			res := struct {
				Types   int   `json:"types"`
				Fields  int   `json:"fields"`
				Methods int   `json:"methods"`
				Rows    []row `json:"rows"`
			}{Types: types, Fields: fields, Methods: methods}
			fullNames := nestedTypeNames(c)
			for i := 0; i < types && len(res.Rows) < 60; i++ {
				full := fullNames[i]
				f0, f1 := fieldAt(i), fieldAt(i+1)
				m0, m1 := methodAt(i), methodAt(i+1)
				if f0 < 0 || f1 < f0 || f1 > fields || m0 < 0 || m1 < m0 || m1 > methods {
					return nil, fmt.Errorf("%s TypeDef %d declares ranges fields[%d:%d] methods[%d:%d] outside the tables", path, i, f0, f1, m0, m1)
				}
				r := row{Type: full, Fields: f1 - f0, Methods: m1 - m0}
				for m := m0; m < m1 && len(r.Names) < 12; m++ {
					if n := c.str(idxAt(c.row(0x06, m), mdO[3], mdW[3])); n != "" {
						r.Names = append(r.Names, n)
					}
				}
				res.Rows = append(res.Rows, r)
			}
			return res, nil
		},
	})
}

// nestedTypeNames resolves every TypeDef row to its namespace-qualified name,
// then rewrites a nested type as Enclosing+Nested from the NestedClass table.
// The table maps a nested TypeDef row to its enclosing row; enclosing rows are
// not guaranteed to come first, so resolution recurses (depth-capped).
func nestedTypeNames(c *cliView) []string {
	tdW, tdO := c.cols(0x02)
	n := c.n(0x02)
	names := make([]string, n)
	for i := range n {
		r := c.row(0x02, i)
		names[i] = c.str(idxAt(r, tdO[1], tdW[1]))
		if ns := c.str(idxAt(r, tdO[2], tdW[2])); ns != "" {
			names[i] = ns + "." + names[i]
		}
	}
	nc := c.n(0x29)
	if nc == 0 {
		return names
	}
	nw, no := c.cols(0x29)
	owner := make(map[int]int, nc)
	for i := range nc {
		r := c.row(0x29, i)
		nested := int(idxAt(r, no[0], nw[0])) - 1
		encl := int(idxAt(r, no[1], nw[1])) - 1
		if nested >= 0 && encl >= 0 && nested < n && encl < n && nested != encl {
			owner[nested] = encl
		}
	}
	var resolve func(int, int) string
	resolve = func(i, depth int) string {
		own, ok := owner[i]
		if !ok || depth > 32 {
			return names[i]
		}
		base := c.str(idxAt(c.row(0x02, i), tdO[1], tdW[1]))
		return resolve(own, depth+1) + "+" + base
	}
	for i := range names {
		names[i] = resolve(i, 0)
	}
	return names
}
