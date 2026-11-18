package main

func init() {
	registerOp(op{
		name:  "inspect_native_exports",
		route: "L",
		needs: true,
		desc:  "export count and symbol-table presence for a PE or ELF image; names stay out because the digest keeps only the count",
		run: func(path string) (any, error) {
			d, err := Probe(path)
			if err != nil {
				return nil, err
			}
			switch d.Kind {
			case "pe", "pe-dotnet", "elf":
			case "macho":
				return skipf("%s: Mach-O exports are covered by inspect_macho; inspect_native_exports reads PE and ELF export tables", path), nil
			default:
				return skipf("%s: kind %s is not a PE or ELF image; inspect_native_exports reads PE and ELF export tables", path, d.Kind), nil
			}
			return struct {
				Kind    string `json:"kind"`
				Format  string `json:"format"`
				Exports int    `json:"exports"`
				Symbols string `json:"symbols"`
			}{Kind: d.Kind, Format: d.Format, Exports: d.Exports, Symbols: d.Symbols}, nil
		},
	})
}
