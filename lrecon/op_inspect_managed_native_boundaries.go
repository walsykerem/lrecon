package main

import "fmt"

func init() {
	registerOp(op{
		name:  "inspect_managed_native_boundaries",
		route: "L",
		needs: true,
		desc:  "ImplMap/P-Invoke listing: managed method, native entry point, module, and whether that module is imported",
		run: func(path string) (any, error) {
			c, err := openCLIView(path)
			if err != nil {
				// A PE that is not a managed assembly is an answer, not a
				// failure. The two magic bytes say so without hashing the
				// whole file for it.
				if h := head(path, 4); len(h) >= 4 && h[0] == 'M' && h[1] == 'Z' {
					return skipf("%s is not a managed assembly (no ECMA-335 CLI header and metadata root)", path), nil
				}
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			imW, imO := c.cols(0x1C)
			mrW, mrO := c.cols(0x1A)
			mdW, mdO := c.cols(0x06)
			tdW, tdO := c.cols(0x02)
			type pinvoke struct {
				Managed string `json:"managed"`
				Native  string `json:"native"`
				Module  string `json:"module"`
				Type    string `json:"type,omitempty"`
			}
			res := struct {
				PInvokes int       `json:"pinvokes"`
				Shown    int       `json:"shown"`
				Modules  []string  `json:"modules"`
				Entries  []pinvoke `json:"entries"`
			}{}
			mods := map[string]bool{}
			for i := 0; i < c.n(0x1C); i++ {
				row := c.row(0x1C, i)
				native := c.str(idxAt(row, imO[2], imW[2]))
				module := ""
				if mi := int(idxAt(row, imO[3], imW[3])); mi > 0 && mi <= c.n(0x1A) {
					module = c.str(idxAt(c.row(0x1A, mi-1), mrO[0], mrW[0]))
				}
				// MemberForwarded coded index: tag 0 = Field, 1 = MethodDef.
				member := idxAt(row, imO[1], imW[1])
				tag := member & 1
				ref := int(member >> 1)
				managed := ""
				owner := ""
				if tag == 1 && ref > 0 && ref <= c.n(0x06) {
					managed = c.str(idxAt(c.row(0x06, ref-1), mdO[3], mdW[3]))
					owner = typeOwner(c, ref, tdW, tdO)
				}
				if managed == "" {
					continue
				}
				res.PInvokes++
				// The listing is capped; pinvokes and shown keep the counts honest.
				if len(res.Entries) < 100 {
					res.Entries = append(res.Entries, pinvoke{managed, native, module, owner})
				}
				mods[module] = true
			}
			res.Shown = len(res.Entries)
			res.Modules = setKeys(mods)
			if res.PInvokes == 0 {
				// The import count is only needed for this line, so the digest
				// that carries it is read here and not on every run.
				imports := 0
				if d, derr := Probe(path); derr == nil {
					imports = len(d.Imports)
				}
				return skipf("%s has no ImplMap rows, so it declares no P/Invoke boundary; %d PE imports", path, imports), nil
			}
			return res, nil
		},
	})
}

// typeOwner walks TypeDef MethodList ranges to name the type owning method ref.
func typeOwner(c *cliView, method int, tdW, tdO []int) string {
	types := c.n(0x02)
	for i := range types {
		td := c.row(0x02, i)
		start := int(idxAt(td, tdO[5], tdW[5]))
		next := c.n(0x06) + 1
		if i+1 < types {
			next = int(idxAt(c.row(0x02, i+1), tdO[5], tdW[5]))
		}
		if method >= start && method < next {
			name := c.str(idxAt(td, tdO[1], tdW[1]))
			ns := c.str(idxAt(td, tdO[2], tdW[2]))
			if ns != "" {
				return ns + "." + name
			}
			return name
		}
	}
	return ""
}
