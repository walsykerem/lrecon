package main

// inspect_machoRow is one mapped section from metaSectionTable, retagged so the
// op's JSON keys stay stable instead of leaking Go field names.
type inspect_machoRow struct {
	Name       string `json:"name"`
	Segment    string `json:"segment,omitempty"`
	Arch       string `json:"arch,omitempty"`
	Address    uint64 `json:"address"`
	Size       uint64 `json:"size"`
	FileOffset uint64 `json:"file_offset"`
}

func init() {
	registerOp(op{
		name:  "inspect_macho",
		route: "L",
		needs: true,
		desc:  "Mach-O slice identity, minos, uuid, dependencies, capability imports, export count, hardening and mapped sections from the on-disk headers",
		run: func(path string) (any, error) {
			d, err := Probe(path)
			if err != nil {
				return nil, err
			}
			if d.Kind != "macho" {
				return skipf("%s: kind %s is not Mach-O; inspect_macho reads Mach-O headers only", path, d.Kind), nil
			}
			secs, err := metaSectionTable(path)
			if err != nil {
				return nil, err
			}
			rows := make([]inspect_machoRow, 0, len(secs))
			for _, s := range secs {
				rows = append(rows, inspect_machoRow{
					Name: s.Name, Segment: s.Seg, Arch: s.Arch,
					Address: s.Addr, Size: s.Size, FileOffset: s.Off,
				})
			}
			// The digest's slices key counts fat slices only; a thin image is
			// still one architecture, which is what this op reports.
			slices := d.Slices
			if d.Format == "thin" {
				slices = 1
			}
			return struct {
				Kind       string             `json:"kind"`
				Format     string             `json:"format"`
				Slices     int                `json:"slices"`
				SliceInfo  []string           `json:"slice_info"`
				MinOS      string             `json:"minos"`
				UUID       string             `json:"uuid"`
				Dylibs     []string           `json:"dylibs"`
				ImportHint []string           `json:"import_hints"`
				Rpaths     []string           `json:"rpaths"`
				Exports    int                `json:"exports"`
				Symbols    string             `json:"symbols"`
				Hardening  []string           `json:"hardening"`
				Sections   []inspect_machoRow `json:"sections"`
			}{
				Kind: d.Kind, Format: d.Format, Slices: slices,
				SliceInfo: d.SliceInfo, MinOS: d.MinOS, UUID: d.UUID,
				Dylibs: d.Dylibs, ImportHint: d.Imports, Rpaths: d.Rpaths,
				Exports: d.Exports, Symbols: d.Symbols,
				Hardening: d.Hardening, Sections: rows,
			}, nil
		},
	})
}
