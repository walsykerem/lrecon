package main

import (
	"fmt"
	"os"
	"strings"
)

// final.md 48: batch_decompile.
func init() {
	registerOp(op{
		name:  "batch_decompile",
		route: "G",
		desc:  "decompile each name/address in LRECON_ARGS and report lines plus pseudocode per function (ghidra headless)",
		needs: true,
		run: func(path string) (any, error) {
			refs, err := nativeList()
			if err != nil {
				// A set-but-useless LRECON_ARGS ("," or " , ") is the caller's
				// mistake, not ours: an empty list says nothing about the
				// binary, and "internal" hides that from triage.
				if strings.Contains(err.Error(), "empty after splitting") {
					return nil, fmt.Errorf("batch_decompile: invalid value %q for LRECON_ARGS: no address or symbol after splitting on commas", os.Getenv("LRECON_ARGS"))
				}
				return nil, err
			}
			return ghidraOp(path, "batch_decompile", refs...)
		},
	})
}
