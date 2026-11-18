package main

import "fmt"

func init() {
	registerOp(op{
		name:  "update_unknown",
		route: "L",
		needs: true,
		desc:  "Update the hypothesis (and optionally the resolution) of a recorded unknown in <state>/unknowns.json, keyed by address.",
		run:   runUpdateUnknown,
	})
}

func runUpdateUnknown(path string) (any, error) {
	job, err := opLoadJob(path)
	if err != nil {
		return nil, err
	}
	if job.Address == "" {
		return nil, fmt.Errorf("update_unknown: job needs \"address\"")
	}
	if job.Hypothesis == "" && job.Resolution == "" {
		return nil, fmt.Errorf("update_unknown: job needs \"hypothesis\" or \"resolution\"")
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
	exists, err := metaReadState(file, metaUnknownsKind, &st)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("update_unknown: no unknowns recorded in %s", root)
	}
	for i := range st.Unknowns {
		u := &st.Unknowns[i]
		if u.Address != job.Address {
			continue
		}
		before := *u
		if job.Hypothesis != "" {
			u.Hypothesis = job.Hypothesis
		}
		if job.Resolution != "" {
			u.Resolution = job.Resolution
			u.Resolved = true
		}
		if err := metaWriteJSON(file, st); err != nil {
			return nil, err
		}
		return map[string]any{
			"updated":       *u,
			"before":        before,
			"count":         len(st.Unknowns),
			"unresolved":    len(metaOpenUnknowns(st)),
			"unknowns_file": file,
		}, nil
	}
	return nil, fmt.Errorf("update_unknown: no unknown at %s in %s", job.Address, file)
}
