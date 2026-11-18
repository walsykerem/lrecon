package main

import "os"

// A REA-style open_binary returns a live handle. lrecon is stateless: it reads
// the bytes once and remembers nothing, so this op answers with the digest
// identity and says the handle is none instead of inventing one.
func init() {
	registerOp(op{
		name:  "open_binary",
		route: "L",
		needs: true,
		desc:  "resolve one binary and return its digest identity (kind, format, size, sha256, gitoid); stateless, lrecon holds no live handle",
		run: func(path string) (any, error) {
			info, err := os.Stat(path)
			if err != nil {
				return nil, err
			}
			if info.IsDir() {
				return skipf("%s is a directory; open_binary wants one binary file", path), nil
			}
			d, err := Probe(path)
			if err != nil {
				return nil, err
			}
			return struct {
				Document   string `json:"document"`
				Handle     string `json:"handle"`
				Kind       string `json:"kind"`
				Format     string `json:"format"`
				Size       int64  `json:"size"`
				SHA256     string `json:"sha256,omitempty"`
				GitOID     string `json:"gitoid,omitempty"`
				HashScope  string `json:"hash_scope"`
				BinarySize int64  `json:"binary_size"`
			}{
				Document:  path,
				Handle:    "none",
				Kind:      d.Kind,
				Format:    d.Format,
				Size:      d.Target.Size,
				SHA256:    d.Target.FileSHA256,
				GitOID:    d.Target.GitOID,
				HashScope: d.Target.HashScope,
				// BinarySize names the on-disk file; Size is the hashed byte count.
				BinarySize: info.Size(),
			}, nil
		},
	})
}
