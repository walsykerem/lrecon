package main

import (
	"fmt"
	"sort"
)

// managedMembers is one assembly's declared surface: full type names and
// "Type::method" pairs, both read straight from the ECMA-335 tables.
type managedMembers struct {
	types   map[string]bool
	methods map[string]bool
}

func init() {
	registerOp(op{
		name:  "compare_managed_members",
		route: "L",
		needs: true,
		desc:  "diff the TypeDef/MethodDef surface of two assemblies (<a>,<b>)",
		run: func(path string) (any, error) {
			left, right, err := opPair(path)
			if err != nil {
				return nil, err
			}
			a, err := managedSurface(left)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", left, err)
			}
			b, err := managedSurface(right)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", right, err)
			}
			res := struct {
				Left            string   `json:"left"`
				Right           string   `json:"right"`
				LeftTypes       int      `json:"left_types"`
				RightTypes      int      `json:"right_types"`
				LeftMethods     int      `json:"left_methods"`
				RightMethods    int      `json:"right_methods"`
				TypesOnlyLeft   []string `json:"types_only_left,omitempty"`
				TypesOnlyRight  []string `json:"types_only_right,omitempty"`
				MethodsOnlyLeft []string `json:"methods_only_left,omitempty"`
				MethodsOnlyRght []string `json:"methods_only_right,omitempty"`
				// cap50 trims the lists; the totals say how much was trimmed.
				TypesOnlyLeftTotal    int `json:"types_only_left_total"`
				TypesOnlyRightTotal   int `json:"types_only_right_total"`
				MethodsOnlyLeftTotal  int `json:"methods_only_left_total"`
				MethodsOnlyRightTotal int `json:"methods_only_right_total"`
			}{Left: left, Right: right,
				LeftTypes: len(a.types), RightTypes: len(b.types),
				LeftMethods: len(a.methods), RightMethods: len(b.methods)}
			typesLeft := onlyIn(setKeys(a.types), setKeys(b.types))
			typesRight := onlyIn(setKeys(b.types), setKeys(a.types))
			methodsLeft := onlyIn(setKeys(a.methods), setKeys(b.methods))
			methodsRight := onlyIn(setKeys(b.methods), setKeys(a.methods))
			res.TypesOnlyLeftTotal, res.TypesOnlyRightTotal = len(typesLeft), len(typesRight)
			res.MethodsOnlyLeftTotal, res.MethodsOnlyRightTotal = len(methodsLeft), len(methodsRight)
			res.TypesOnlyLeft = cap50(typesLeft)
			res.TypesOnlyRight = cap50(typesRight)
			res.MethodsOnlyLeft = cap50(methodsLeft)
			res.MethodsOnlyRght = cap50(methodsRight)
			return res, nil
		},
	})
}

// managedSurface reads TypeDef and MethodDef rows and pairs each method with the
// type whose MethodList range covers it.
func managedSurface(path string) (managedMembers, error) {
	c, err := openCLIView(path)
	if err != nil {
		return managedMembers{}, err
	}
	out := managedMembers{types: map[string]bool{}, methods: map[string]bool{}}
	tdW, tdO := c.cols(0x02)
	mdW, mdO := c.cols(0x06)
	type rangeStart struct {
		at   int
		name string
	}
	var starts []rangeStart
	for i := 0; i < c.n(0x02); i++ {
		row := c.row(0x02, i)
		name := c.str(idxAt(row, tdO[1], tdW[1]))
		ns := c.str(idxAt(row, tdO[2], tdW[2]))
		full := name
		if ns != "" {
			full = ns + "." + name
		}
		out.types[full] = true
		if at := int(idxAt(row, tdO[5], tdW[5])); at > 0 {
			starts = append(starts, rangeStart{at, full})
		}
	}
	sort.Slice(starts, func(a, b int) bool { return starts[a].at < starts[b].at })
	for i := 0; i < c.n(0x06); i++ {
		name := c.str(idxAt(c.row(0x06, i), mdO[3], mdW[3]))
		if name == "" {
			continue
		}
		owner := ""
		for _, s := range starts {
			if s.at > i+1 {
				break
			}
			owner = s.name
		}
		if owner != "" {
			out.methods[owner+"::"+name] = true
		}
	}
	return out, nil
}

func setKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func cap50(in []string) []string {
	if len(in) > 50 {
		return in[:50]
	}
	return in
}
