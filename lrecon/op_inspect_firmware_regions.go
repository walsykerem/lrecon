package main

import (
	"fmt"
	"strings"
)

// final.md: inspect_firmware_regions.
func init() {
	registerOp(op{
		name:  "inspect_firmware_regions",
		route: "L",
		desc:  "carve known firmware/rootfs container magics out of the image: firmware kind plus byte offset and container type per region",
		needs: true,
		run: func(path string) (any, error) {
			d, err := Probe(path)
			if err != nil {
				return nil, err
			}
			kind, parts, notes := d.FirmwareKind, d.FirmwareParts, d.Notes
			if kind == "" {
				// Probe verified a structured format: container-shaped bytes
				// inside a Mach-O or ELF are that format's own data, not carved
				// firmware, so a region list over it would be invented.
				if d.Kind != "unknown" {
					detected := d.Kind
					if d.Format != "" {
						detected = d.Kind + "/" + d.Format
					}
					return skipf("%s: %s is not a firmware image; a container carve over a verified format would invent regions", path, detected), nil
				}
				// A flash dump may carry a bootloader header before its first
				// container; extract_firmware scans the whole image, so the
				// region list must too instead of trusting the offset-0 kind.
				b, err := opRead(path, maxFirmwareScan)
				if err != nil {
					return nil, err
				}
				hits, capped := firmwareHits(b)
				if len(hits) == 0 {
					return skipf("%s: %s is not a firmware image and holds no known container magic", path, d.Kind), nil
				}
				kind = hits[0].name
				parts = make([]string, 0, len(hits))
				for _, h := range hits {
					parts = append(parts, fmt.Sprintf("0x%08x %s", h.off, h.name))
				}
				if capped {
					notes = append(notes, fmt.Sprintf("firmware: parts capped at %d", maxFirmwareParts))
				}
				// No truncation note is needed: opRead refuses a file over
				// maxFirmwareScan instead of reading a prefix of it.
			}
			// A carved region list over a header the validator refused is not
			// the same answer as one over a valid header; carry the refusal.
			for _, s := range d.Skipped {
				if strings.HasPrefix(s.Reason, "firmware-ext") {
					notes = append(notes, "firmware-ext: "+s.Reason+": "+s.Detail)
				}
			}
			// A recognized wrapper (gzip, xz) legitimately holds no carved
			// container, so an empty region list is an answer here, not a failure.
			return struct {
				Kind     string   `json:"kind"`
				FileSize int64    `json:"file_size"`
				Regions  int      `json:"regions"`
				Detail   []string `json:"region_detail"`
				Notes    []string `json:"notes,omitempty"`
			}{kind, d.FileSize, len(parts), parts, notes}, nil
		},
	})
}
