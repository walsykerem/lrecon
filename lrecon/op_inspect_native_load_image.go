package main

import (
	"fmt"
	"os"
)

func init() {
	registerOp(op{
		name:  "inspect_native_load_image",
		route: "L",
		needs: true,
		desc:  "refuse load-image verification: lrecon reads on-disk headers and never maps a DOS MZ/COM image or its runtime state",
		run: func(path string) (any, error) {
			// The refusal must not hide a bad target: every sibling op reports a
			// missing path as an io error, so stat before refusing.
			st, err := os.Stat(path)
			if err != nil {
				return nil, err
			}
			if st.IsDir() {
				return nil, fmt.Errorf("%s is a directory", path)
			}
			return skipf("%s: lrecon reads on-disk headers only and never maps a loaded image, so DOS MZ/COM load-image memory digests, relocations and entry state cannot be reported", path), nil
		},
	})
}
