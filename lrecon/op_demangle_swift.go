package main

import (
	"fmt"
	"strings"
)

// swiftDemangled is one symbol and its decoded Swift name.
type swiftDemangled struct {
	Mangled   string `json:"mangled"`
	Demangled string `json:"demangled"`
	Rest      string `json:"rest,omitempty"`
}

func init() {
	registerOp(op{
		name:  "demangle_swift",
		route: "L",
		needs: true,
		desc:  "decode $s/_$s length-prefixed Swift symbols into module.type.function",
		run: func(path string) (any, error) {
			paths, err := symbolPaths(path)
			if err != nil {
				return nil, err
			}
			type entry struct {
				Path    string           `json:"path"`
				Symbols int              `json:"symbols"`
				Mangled int              `json:"swift_symbols"`
				Names   []swiftDemangled `json:"names,omitempty"`
			}
			var out []entry
			for _, p := range paths {
				d, err := Probe(p)
				if err != nil {
					return nil, err
				}
				names, _, total, err := manglingNames(p, &d)
				if err != nil && len(names) == 0 {
					return nil, fmt.Errorf("%s: %w", p, err)
				}
				e := entry{Path: p, Symbols: total}
				for _, n := range names {
					if manglingSwiftShape(n) == "" {
						continue
					}
					e.Mangled++
					if len(e.Names) >= 24 {
						continue
					}
					dm, rest := demangleSwift(n)
					e.Names = append(e.Names, swiftDemangled{Mangled: n, Demangled: dm, Rest: rest})
				}
				out = append(out, e)
			}
			res := struct {
				Targets []entry `json:"targets"`
				Swift   int     `json:"swift_symbols"`
			}{Targets: out}
			for _, e := range out {
				res.Swift += e.Mangled
			}
			if res.Swift == 0 {
				return skipf("%s has no $s-mangled Swift symbols", path), nil
			}
			return res, nil
		},
	})
}

// symbolPaths splits an optional "a,b" pair of binaries; a single path stays one.
func symbolPaths(path string) ([]string, error) {
	if strings.Contains(path, ",") {
		l, r, err := opPair(path)
		if err != nil {
			return nil, err
		}
		return []string{l, r}, nil
	}
	return []string{path}, nil
}

// demangleSwift decodes the plain identifier chain: each component is a decimal
// length followed by that many bytes.
func demangleSwift(sym string) (string, string) {
	body := strings.TrimPrefix(strings.TrimPrefix(sym, "_"), "$s")
	var parts []string
	rest := ""
	for {
		i := 0
		for i < len(body) && body[i] >= '0' && body[i] <= '9' {
			i++
		}
		if i == 0 || i > 2 || i >= len(body) {
			rest = body
			break
		}
		n := 0
		for _, c := range body[:i] {
			n = n*10 + int(c-'0')
		}
		if n <= 0 || i+n > len(body) {
			rest = body
			break
		}
		parts = append(parts, body[i:i+n])
		body = body[i+n:]
		if len(parts) >= 6 {
			rest = body
			break
		}
	}
	if len(parts) == 0 {
		return "", rest
	}
	return strings.Join(parts, "."), rest
}
