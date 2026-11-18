package main

import "strings"

// rustDigest in native.go settles the producer for a native image: a rustc
// version string or a registry crate path proves a Rust build. This op reports
// that settled answer instead of re-scanning the bytes.
func init() {
	registerOp(op{
		name:  "inspect_rust_binary",
		route: "L",
		needs: true,
		desc:  "Rust producer string plus the crate names recovered from cargo registry paths",
		run: func(path string) (any, error) {
			d, err := Probe(path)
			if err != nil {
				return nil, err
			}
			switch d.Kind {
			case "elf", "macho", "pe":
			default:
				return skipf("%s: %s is not a native image; Rust code is compiled into ELF, Mach-O or PE", path, d.Kind), nil
			}
			if !strings.HasPrefix(d.Toolchain, "rustc") {
				return skipf("%s: %s has no rustc marker or Rust crate path; not a Rust build", path, d.Kind), nil
			}
			var syms []string
			for _, c := range d.Capabilities {
				if strings.HasPrefix(c, "rustsym:") {
					syms = append(syms, c)
				}
			}
			return struct {
				Kind      string   `json:"kind"`
				Toolchain string   `json:"toolchain"`
				Crates    []string `json:"crates"`
				Symbols   []string `json:"symbols,omitempty"`
			}{d.Kind, d.Toolchain, d.RustCrates, syms}, nil
		},
	})
}
