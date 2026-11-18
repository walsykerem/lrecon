package main

func init() {
	registerOp(op{
		name:  "inspect_artifact",
		route: "L",
		needs: true,
		desc:  "open one artifact for inspection and return the digest inventory (kind, format, hashes, exports, hardening); one-shot read, no handle is kept",
		run: func(path string) (any, error) {
			d, err := Probe(path)
			if err != nil {
				return nil, err
			}
			return struct {
				Document     string   `json:"document"`
				Kind         string   `json:"kind"`
				Format       string   `json:"format"`
				Size         int64    `json:"size"`
				SHA256       string   `json:"sha256,omitempty"`
				Slices       int      `json:"slices"`
				Toolchain    string   `json:"toolchain,omitempty"`
				Exports      int      `json:"exports"`
				Hardening    []string `json:"hardening"`
				Capabilities []string `json:"capabilities,omitempty"`
				Notes        []string `json:"notes,omitempty"`
			}{
				Document:     path,
				Kind:         d.Kind,
				Format:       d.Format,
				Size:         d.Target.Size,
				SHA256:       d.Target.FileSHA256,
				Slices:       d.Slices,
				Toolchain:    d.Toolchain,
				Exports:      d.Exports,
				Hardening:    d.Hardening,
				Capabilities: d.Capabilities,
				Notes:        d.Notes,
			}, nil
		},
	})
}
