package main

import (
	"fmt"
	"strings"
)

func init() {
	registerOp(op{
		name:  "binary_overview",
		route: "L",
		needs: true,
		desc:  "one-screen answer from the digest: kind, format, arch/slices, toolchain, export count and hardening",
		run: func(path string) (any, error) {
			d, err := Probe(path)
			if err != nil {
				return nil, err
			}
			format := d.Format
			if format == "" {
				format = "unknown"
			}
			toolchain := d.Toolchain
			if toolchain == "" {
				toolchain = "unknown"
			}
			hardening := strings.Join(d.Hardening, ", ")
			if hardening == "" {
				hardening = "none reported"
			}
			return struct {
				Summary         string   `json:"summary"`
				Kind            string   `json:"kind"`
				Format          string   `json:"format"`
				Slices          int      `json:"slices"`
				Architectures   []string `json:"architectures,omitempty"`
				Toolchain       string   `json:"toolchain"`
				Exports         int      `json:"exports"`
				Symbols         string   `json:"symbols,omitempty"`
				Hardening       []string `json:"hardening"`
				Notes           []string `json:"notes,omitempty"`
				ContractVersion int      `json:"contract_version"`
			}{
				Summary: fmt.Sprintf("%s %s: %d slice(s), %s, %d exports, hardening %s",
					d.Kind, format, d.Slices, toolchain, d.Exports, hardening),
				Kind:            d.Kind,
				Format:          format,
				Slices:          d.Slices,
				Architectures:   d.SliceInfo,
				Toolchain:       d.Toolchain,
				Exports:         d.Exports,
				Symbols:         d.Symbols,
				Hardening:       d.Hardening,
				Notes:           d.Notes,
				ContractVersion: d.ContractVersion,
			}, nil
		},
	})
}
