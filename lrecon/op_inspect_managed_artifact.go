package main

// The artifact-level managed answer: which CLI runtime built it and how many
// rows each metadata table holds. openCLIView is the same table decoder
// inspect_managed_members uses; this op only counts, it does not list members.
func init() {
	registerOp(op{
		name:  "inspect_managed_artifact",
		route: "L",
		needs: true,
		desc:  "ECMA-335 CLI metadata: runtime version, streams and the TypeDef/Field/MethodDef row counts",
		run: func(path string) (any, error) {
			d, err := Probe(path)
			if err != nil {
				return nil, err
			}
			if d.Kind != "pe-dotnet" {
				return skipf("%s: %s is not a managed assembly (no ECMA-335 CLI header and metadata root)", path, d.Kind), nil
			}
			c, err := openCLIView(path)
			if err != nil {
				return skipf("%s: managed metadata root is not a readable BSJB table stream: %v", path, err), nil
			}
			tables := 0
			for id := 0; id <= 0x2C; id++ {
				if c.n(id) > 0 {
					tables++
				}
			}
			return struct {
				Kind     string   `json:"kind"`
				Runtime  string   `json:"runtime,omitempty"`
				Streams  []string `json:"streams,omitempty"`
				Tables   int      `json:"tables"`
				Types    int      `json:"types"`
				TypeRefs int      `json:"typerefs"`
				Fields   int      `json:"fields"`
				Methods  int      `json:"methods"`
				Assembly int      `json:"assembly"`
				AsmRefs  int      `json:"assembly_refs"`
			}{
				Kind: d.Kind, Runtime: c.md.version, Streams: c.md.streams, Tables: tables,
				Types: c.n(0x02), TypeRefs: c.n(0x01), Fields: c.n(0x04), Methods: c.n(0x06),
				Assembly: c.n(0x20), AsmRefs: c.n(0x23),
			}, nil
		},
	})
}
