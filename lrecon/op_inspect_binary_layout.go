package main

func init() {
	registerOp(op{
		name:  "inspect_binary_layout",
		route: "L",
		needs: true,
		desc:  "file-backed section layout for ELF, Mach-O and PE: name, address, file offset, size and exec flag",
		run: func(path string) (any, error) {
			d, err := Probe(path)
			if err != nil {
				return nil, err
			}
			if !ghidraNativeKinds[d.Kind] {
				format := d.Format
				if format == "" {
					format = "unknown"
				}
				return skipf("%s: per-section layout not computed for kind %q; digest reports kind=%s format=%s slices=%d exports=%d",
					path, d.Kind, d.Kind, format, d.Slices, d.Exports), nil
			}
			format, secs, err := nativeSections(path)
			if err != nil {
				return nil, err
			}
			type row struct {
				Name   string `json:"name"`
				Addr   uint64 `json:"address"`
				Offset uint64 `json:"file_offset"`
				Size   uint64 `json:"size"`
				Exec   bool   `json:"exec"`
			}
			rows := make([]row, 0, len(secs))
			for _, s := range secs {
				rows = append(rows, row{s.Name, s.Addr, s.Off, s.Size, s.Exec})
			}
			res := struct {
				Format   string `json:"format"`
				Sections []row  `json:"sections"`
				Note     string `json:"note,omitempty"`
			}{Format: format, Sections: rows}
			if d.Slices > 1 {
				// nativeSections reads one slice; saying which keeps the layout honest.
				res.Note = "fat binary: first slice only"
			}
			return res, nil
		},
	})
}
