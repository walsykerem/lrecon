package main

import "sort"

// magicSwitchKinds is the vocabulary the magic switch in Probe can name before
// any reader runs (detect.go:96-166). Reader formats are derived live from the
// registry, so a new reader shows up here without editing this file.
var magicSwitchKinds = []string{
	"android-manifest", "asar", "car", "dex", "elf", "firmware", "flutter",
	"hermes", "macho", "nib", "pcap", "pe", "plist", "signature", "sqlite",
	"text", "wasm", "zip",
}

// formatName is the one place the digest kind and the advertised format name
// differ; every coverage lookup goes through it so the two never drift.
func formatName(kind string) string {
	if kind == "macho" {
		return "mach-o"
	}
	return kind
}

type formatCoverage struct {
	SupportedFormats []string `json:"supported_formats"`
	ReaderCount      int      `json:"reader_count"`
	MagicSwitchKinds []string `json:"magic_switch_kinds"`
	TargetKind       string   `json:"target_kind,omitempty"`
	Covered          *bool    `json:"covered,omitempty"`
	Notes            []string `json:"notes,omitempty"`
}

func init() {
	registerOp(op{
		name:  "inspect_format_coverage",
		route: "L",
		needs: false,
		desc:  "Every format lrecon can name: the magic switch kinds plus the live reader registry, with an optional target checked against that set.",
		run:   runInspectFormatCoverage,
	})
}

func runInspectFormatCoverage(path string) (any, error) {
	set := make(map[string]bool, len(magicSwitchKinds)+len(readers))
	for _, kind := range magicSwitchKinds {
		set[formatName(kind)] = true
	}
	for _, r := range readers {
		set[r.format] = true
	}
	formats := make([]string, 0, len(set))
	for f := range set {
		formats = append(formats, f)
	}
	sort.Strings(formats)
	out := formatCoverage{
		SupportedFormats: formats,
		ReaderCount:      len(readers),
		MagicSwitchKinds: magicSwitchKinds,
	}
	if path == "" {
		return out, nil
	}
	d, err := Probe(path)
	if err != nil {
		return nil, err
	}
	covered := set[formatName(d.Kind)]
	out.TargetKind = d.Kind
	out.Covered = &covered
	if d.Kind == "unknown" {
		out.Notes = append(out.Notes, "uncovered-format")
	}
	return out, nil
}
