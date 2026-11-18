package main

// pyc.go owns the whole CPython answer: magic-to-version, marshal walk, and the
// refusal reasons. This op reports that digest for one .pyc; it never decodes a
// second time, so a file that failed the marshal walk cannot come back as a
// clean list of qualnames here.
func init() {
	registerOp(op{
		name:  "inspect_python_pyc",
		route: "L",
		needs: true,
		desc:  "CPython .pyc: version from the magic, code-object qualnames and source file",
		run: func(path string) (any, error) {
			d, err := Probe(path)
			if err != nil {
				return nil, err
			}
			if d.Kind != "pyc" {
				return skipf("%s: %s is not a CPython .pyc (no magic with 0d 0a in bytes 2-3)", path, d.Kind), nil
			}
			if len(d.Skipped) > 0 {
				s := d.Skipped[0]
				return skipf("%s: %s: %s", path, s.Reason, s.Detail), nil
			}
			return struct {
				Toolchain    string   `json:"toolchain"`
				Qualnames    []string `json:"qualnames"`
				Capabilities []string `json:"capabilities,omitempty"`
				Notes        []string `json:"notes,omitempty"`
			}{d.Toolchain, d.Imports, d.Capabilities, d.Notes}, nil
		},
	})
}
