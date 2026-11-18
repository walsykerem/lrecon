package main

import "fmt"

// final.md: inspect_plist.
func init() {
	registerOp(op{
		name:  "inspect_plist",
		route: "L",
		desc:  "property names from an XML or binary property list, with the bundle identity and version strings printed next to the keys that carry them",
		needs: true,
		run: func(path string) (any, error) {
			d, err := Probe(path)
			if err != nil {
				return nil, err
			}
			if d.Kind != "plist" {
				return skipf("%s: %s is not a property list", path, d.Kind), nil
			}
			notes := d.Notes
			if len(d.PlistKeys) == 0 {
				// An array-only plist has no dictionary keys; saying so keeps an
				// empty list from reading as a failed parse.
				notes = append(notes, fmt.Sprintf("no dictionary keys in the first %d bytes", maxPlistBytes))
			}
			return struct {
				Keys  []string `json:"keys"`
				Notes []string `json:"notes,omitempty"`
			}{d.PlistKeys, notes}, nil
		},
	})
}
