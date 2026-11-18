package main

import (
	"fmt"
	"sort"
)

// metaMemberChange is one bundle member that appeared, disappeared or changed
// bytes between two builds.
type metaMemberChange struct {
	Name      string `json:"name"`
	Change    string `json:"change"` // added|removed|changed
	OldSHA256 string `json:"old_sha256,omitempty"`
	NewSHA256 string `json:"new_sha256,omitempty"`
}

func init() {
	registerOp(op{
		name:  "compare_bundles",
		route: "L",
		needs: true,
		desc:  "Compare two bundle directories or zip-family archives (apk/aab/ipa/hap) member by member: name, change kind and both sha256 values.",
		run:   runCompareBundles,
	})
}

func runCompareBundles(path string) (any, error) {
	job, err := metaLoadJob(path)
	if err != nil {
		return nil, err
	}
	if job.Old == "" || job.New == "" {
		return nil, fmt.Errorf("compare_bundles: job needs \"old\" and \"new\" bundle paths")
	}
	oldM, oldFmt, err := metaArchiveMembers(job.Old)
	if err != nil {
		return nil, fmt.Errorf("old: %w", err)
	}
	newM, newFmt, err := metaArchiveMembers(job.New)
	if err != nil {
		return nil, fmt.Errorf("new: %w", err)
	}
	changes := []metaMemberChange{}
	names := map[string]bool{}
	for n := range oldM {
		names[n] = true
	}
	for n := range newM {
		names[n] = true
	}
	ordered := make([]string, 0, len(names))
	for n := range names {
		ordered = append(ordered, n)
	}
	sort.Strings(ordered)
	for _, n := range ordered {
		x, aok := oldM[n]
		y, bok := newM[n]
		switch {
		case !aok:
			changes = append(changes, metaMemberChange{Name: n, Change: "added", NewSHA256: y})
		case !bok:
			changes = append(changes, metaMemberChange{Name: n, Change: "removed", OldSHA256: x})
		case x != y:
			changes = append(changes, metaMemberChange{Name: n, Change: "changed", OldSHA256: x, NewSHA256: y})
		}
	}
	return map[string]any{
		"old":       map[string]any{"path": job.Old, "format": oldFmt, "members": len(oldM)},
		"new":       map[string]any{"path": job.New, "format": newFmt, "members": len(newM)},
		"changes":   changes,
		"count":     len(changes),
		"added":     metaCountChange(changes, "added"),
		"removed":   metaCountChange(changes, "removed"),
		"changed":   metaCountChange(changes, "changed"),
		"identical": len(changes) == 0,
	}, nil
}

func metaCountChange(cs []metaMemberChange, kind string) int {
	n := 0
	for _, c := range cs {
		if c.Change == kind {
			n++
		}
	}
	return n
}
