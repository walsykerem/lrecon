package main

import (
	"fmt"
	"strings"
)

// metaUnknown is one entry in `unknowns.json`: an address nobody has explained
// yet, the bytes that are there, the hypothesis about them and, once resolved,
// the answer (verify_unknown_resolution re-reads those bytes to check it).
type metaUnknown struct {
	Address    string `json:"address"`
	Bytes      string `json:"bytes,omitempty"`
	Section    string `json:"section,omitempty"`
	Hypothesis string `json:"hypothesis"`
	Resolved   bool   `json:"resolved"`
	Resolution string `json:"resolution,omitempty"`
	Created    string `json:"created"`
}

type metaUnknownState struct {
	Kind     string        `json:"kind"`
	Unknowns []metaUnknown `json:"unknowns"`
}

const metaUnknownsKind = "lrecon.unknowns/1"

func init() {
	registerOp(op{
		name:  "record_unknown",
		route: "L",
		needs: true,
		desc:  "Persist one unexplained address, its bytes and the current hypothesis to <state>/unknowns.json; bytes are read from the binary when the job does not supply them.",
		run:   runRecordUnknown,
	})
}

func runRecordUnknown(path string) (any, error) {
	job, err := metaLoadJob(path)
	if err != nil {
		return nil, err
	}
	if job.Address == "" {
		return nil, fmt.Errorf("record_unknown: job needs \"address\" (and \"file\" to read the bytes from)")
	}
	entry := metaUnknown{
		Address:    job.Address,
		Bytes:      strings.TrimSpace(strings.ToLower(job.Bytes)),
		Hypothesis: job.Hypothesis,
		Created:    metaNow(),
	}
	if entry.Bytes == "" && job.File != "" {
		addr, err := metaParseAddr(job.Address)
		if err != nil {
			return nil, err
		}
		place, err := metaLocate(job.File, addr)
		if err != nil {
			return nil, err
		}
		// An address that does not map to a file offset cannot be re-read, so a
		// record built from it would be unverifiable forever: refuse it instead
		// of storing a silent hole. The caller may still supply "bytes".
		if !place.Exact {
			return nil, fmt.Errorf("record_unknown: address %s is not mapped to a file offset in %s", job.Address, job.File)
		}
		b := readFileAt(job.File, place.Offset, 16)
		if len(b) == 0 {
			return nil, fmt.Errorf("record_unknown: address %s maps to file offset %d of %s, but no bytes could be read there", job.Address, place.Offset, job.File)
		}
		entry.Bytes, entry.Section = metaHex(b), place.Section
	}
	root, err := metaStateRoot(path, job)
	if err != nil {
		return nil, err
	}
	file, err := metaStateFile(root, "unknowns.json")
	if err != nil {
		return nil, err
	}
	var st metaUnknownState
	if _, err := metaReadState(file, metaUnknownsKind, &st); err != nil {
		return nil, err
	}
	for _, u := range st.Unknowns {
		if u.Address == entry.Address {
			return nil, fmt.Errorf("record_unknown: state conflict: %s is already recorded (use update_unknown)", entry.Address)
		}
	}
	st.Kind = metaUnknownsKind
	st.Unknowns = append(st.Unknowns, entry)
	if err := metaWriteJSON(file, st); err != nil {
		return nil, err
	}
	return map[string]any{
		"recorded":      entry,
		"count":         len(st.Unknowns),
		"unresolved":    len(metaOpenUnknowns(st)),
		"unknowns_file": file,
	}, nil
}

func metaOpenUnknowns(st metaUnknownState) []metaUnknown {
	var open []metaUnknown
	for _, u := range st.Unknowns {
		if !u.Resolved {
			open = append(open, u)
		}
	}
	return open
}
