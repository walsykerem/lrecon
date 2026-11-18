package main

import (
	"fmt"
	"runtime"
	"sort"
	"sync"
)

// Witness is one byte range a reader actually looked at, tagged with the
// derivation class that produced it. A claim needs two of them from different
// classes on disjoint ranges: the same rule counted twice is one witness.
type Witness struct {
	Axis  string
	Class string
	Value string
	Start int64
	End   int64
}

// witnessClasses freezes one class per call site, so the class can never be
// derived from the bytes it is supposed to be independent of.
var (
	witnessMu      sync.Mutex
	witnessClasses = map[string]string{}
)

func callerSite(skip int) string {
	_, file, line, ok := runtime.Caller(skip)
	if !ok {
		return "unknown:0"
	}
	return fmt.Sprintf("%s:%d", file, line)
}

// witness is the only writer of Digest.witnesses. The call site, not the caller
// and not the bytes, decides the class: a second class from one site panics.
func (d *Digest) witness(w Witness) {
	d.witnessAt(callerSite(2), w)
}

func (d *Digest) witnessAt(site string, w Witness) {
	witnessMu.Lock()
	defer witnessMu.Unlock()
	if cls, ok := witnessClasses[site]; ok && cls != w.Class {
		panic(fmt.Sprintf("witness class at %s frozen to %q, got %q", site, cls, w.Class))
	}
	witnessClasses[site] = w.Class
	d.witnesses = append(d.witnesses, w)
	d.BytesScanned = witnessUnion(d.witnesses)
}

// witnessed reports whether value carries two classes on disjoint ranges. One
// class, or two that overlap, is a hint rather than a finding.
func (d *Digest) witnessed(value string) bool {
	byClass := map[string][][2]int64{}
	for _, w := range d.witnesses {
		if w.Value == value {
			byClass[w.Class] = append(byClass[w.Class], spanOf(w))
		}
	}
	merged := map[string][][2]int64{}
	classes := make([]string, 0, len(byClass))
	for class, spans := range byClass {
		merged[class] = mergeSpans(spans)
		classes = append(classes, class)
	}
	for i := 0; i < len(classes); i++ {
		for j := i + 1; j < len(classes); j++ {
			if disjointSpans(merged[classes[i]], merged[classes[j]]) {
				return true
			}
		}
	}
	return false
}

// witnessUnion is bytes_scanned: the union of every recorded span, so a note
// read twice or a range read again does not inflate coverage.
func witnessUnion(ws []Witness) int64 {
	spans := make([][2]int64, 0, len(ws))
	for _, w := range ws {
		if w.End > w.Start {
			spans = append(spans, [2]int64{w.Start, w.End})
		}
	}
	var total int64
	for _, s := range mergeSpans(spans) {
		total += s[1] - s[0]
	}
	return total
}

// spanOf keeps a zero-length witness as the single byte it points at, so it
// merges with whatever touches it instead of vanishing from the overlap check.
func spanOf(w Witness) [2]int64 {
	if w.End <= w.Start {
		return [2]int64{w.Start, w.Start + 1}
	}
	return [2]int64{w.Start, w.End}
}

// mergeSpans sorts, then folds overlapping and adjacent ranges into one run.
func mergeSpans(spans [][2]int64) [][2]int64 {
	if len(spans) == 0 {
		return nil
	}
	sorted := spans
	if !sortedByStart(spans) {
		sorted = make([][2]int64, len(spans))
		copy(sorted, spans)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i][0] < sorted[j][0] })
	}
	out := [][2]int64{sorted[0]}
	for _, s := range sorted[1:] {
		last := &out[len(out)-1]
		if s[0] <= last[1] {
			if s[1] > last[1] {
				last[1] = s[1]
			}
			continue
		}
		out = append(out, s)
	}
	return out
}

// sortedByStart reports whether spans already run in start order, the shape a
// reader emits when it scans forward. Skipping the copy and the sort there is
// free: mergeSpans never writes back into the slice it was handed.
func sortedByStart(spans [][2]int64) bool {
	for i := 1; i < len(spans); i++ {
		if spans[i][0] < spans[i-1][0] {
			return false
		}
	}
	return true
}

func disjointSpans(a, b [][2]int64) bool {
	for _, x := range a {
		for _, y := range b {
			if x[0] < y[1] && y[0] < x[1] {
				return false
			}
		}
	}
	return true
}
