package main

import (
	"fmt"
	"strings"
	"sync"
)

// Skip is a refusal that names its reason from the closed set the reader
// registered. Free text never reaches the field: a reason outside the set is
// replaced, so a consumer can switch on reasons without eating prose.
type Skip struct {
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// Coverage counts what happened to each unit a reader looked at: parsed, refused
// with a reason, or matched by no rule. It is only present when a reader ran.
type Coverage struct {
	Parsed  int `json:"parsed"`
	Skipped int `json:"skipped"`
	Unknown int `json:"unknown"`
}

// activeReasons is the set one reader declared, built from the registry for the
// duration of a single call. skip refuses a reason outside it instead of
// silently rewriting the value. The set is package global, so the mutex keeps
// the reader that publishes it and the reader that reads it from crossing.
var (
	activeReasonsMu sync.Mutex
	activeReasons   map[string]bool
)

// setActiveReasons publishes the set of the reader that is running.
func setActiveReasons(set map[string]bool) {
	activeReasonsMu.Lock()
	activeReasons = set
	activeReasonsMu.Unlock()
}

// clearActiveReasons drops the set again: the next reader publishes its own.
func clearActiveReasons() {
	activeReasonsMu.Lock()
	activeReasons = nil
	activeReasonsMu.Unlock()
}

// takeActiveReasons publishes the set when no reader owns it yet and reports
// whether the caller took ownership. The owner clears it again when it is
// done, so a reader that runs outside the dispatcher can declare its reasons
// without racing the one that does.
func takeActiveReasons(set map[string]bool) bool {
	activeReasonsMu.Lock()
	defer activeReasonsMu.Unlock()
	if activeReasons != nil {
		return false
	}
	activeReasons = set
	return true
}

// undeclaredReason reports that the running reader did not declare the
// reason. No reader running means no claim to check against: the reason is
// kept raw.
func undeclaredReason(reason string) bool {
	activeReasonsMu.Lock()
	defer activeReasonsMu.Unlock()
	return activeReasons != nil && !activeReasons[reason]
}

func (d *Digest) skip(reason, detail string) {
	if undeclaredReason(reason) && registeredReason(reason) {
		d.reasonErrs = append(d.reasonErrs, fmt.Sprintf("reason %q not declared by reader (field %s)", reason, fieldOf(reason)))
	}
	if d.Coverage == nil {
		d.Coverage = &Coverage{}
	}
	d.Skipped = append(d.Skipped, Skip{Reason: reason, Detail: strings.TrimSpace(detail)})
	d.Coverage.Skipped++
}

// parsed and unparsed count coverage units for a reader: one call per record it
// either decoded or could not attribute.
func (d *Digest) parsed() {
	if d.Coverage == nil {
		d.Coverage = &Coverage{}
	}
	d.Coverage.Parsed++
}

func (d *Digest) unparsed() {
	if d.Coverage == nil {
		d.Coverage = &Coverage{}
	}
	d.Coverage.Unknown++
}

// complete reports whether an absence is an answer about the whole target: a
// regular file that was read end to end and was not cut. After a partial read
// "not detected" is a claim nobody made, so the honest value is not_scanned.
func (d Digest) complete() bool {
	return d.FileSize > 0 && !d.Truncated && d.BytesScanned >= d.FileSize
}

// gateAbsence runs once per digest and downgrades every not-found answer to
// not_scanned when the scan could not see the whole file. Presence evidence is
// untouched: a token that was seen is still a finding on a cut read. An empty
// JIT or names field is absence too, not an answer.
func (d *Digest) gateAbsence() {
	if d.complete() && !parseFailed(*d) {
		return
	}
	// ponytail: header-only readers (v8-cache, php-opcache) voluntarily stop
	// at the header, so their completeness caveat is not a cut read. A pin
	// here would be honest about not_scanned for truncated cache files,
	// though — upgrade path: track whether reader set Truncated.
	headerOnly := d.Kind == "v8-cache" || d.Kind == "php-opcache"
	if !headerOnly && len(d.Constants) == 1 && d.Constants[0] == constNotDetected {
		d.Constants = consts{constNotScanned}
	}
	if d.JIT == "" || d.JIT == jitNotDetected {
		d.JIT = constNotScanned
	}
	if d.Names == "" || d.Names == nameNotRecovered {
		d.Names = constNotScanned
	}
}

// coverageClaim bounds the counts with their denominator N: the number of units
// the same scan attributed (parsed, refused, or matched by no rule). A reader
// that never ran has no N to state, so the line says "of N unknown" instead of
// dropping the denominator. The count prefix stays first for consumers that
// already parse that line, and N rides on the tail to keep the 4096-byte text
// budget.
func (d Digest) coverageClaim() string {
	c := d.Coverage
	if c == nil {
		return "of N unknown"
	}
	n := c.Parsed + c.Skipped + c.Unknown
	return fmt.Sprintf("parsed:%d skipped:%d unknown:%d N=%d", c.Parsed, c.Skipped, c.Unknown, n)
}

// scanned records a sequential read as a span, so a thin answer on a large file
// is visible and a re-read of the same bytes is not counted twice.
func (d *Digest) scanned(n int64) {
	d.scannedAt(d.readEnd(), n)
}

// scannedAt records a read at an explicit offset. A ReadAt or a section body is
// not on the sequential cursor, so attributing it to readEnd would invent bytes
// nobody read.
func (d *Digest) scannedAt(off, n int64) {
	if n <= 0 {
		return
	}
	start := max(off, 0)
	// The offset is an upper bound, not a file fact: a reader that hops back or
	// reads a section twice can push it past EOF. Clamping keeps bytes_scanned a
	// coverage number (never more than the file) instead of a read counter.
	end := start + n
	if d.FileSize > 0 {
		if start >= d.FileSize {
			return
		}
		if end > d.FileSize {
			end = d.FileSize
		}
	}
	d.witnessAt(callerSite(2), Witness{Axis: "read", Class: "read", Value: "read", Start: start, End: end})
}

// readEnd is the read cursor: the furthest byte a sequential read reached.
func (d *Digest) readEnd() int64 {
	var end int64
	for _, w := range d.witnesses {
		if w.Axis == "read" && w.End > end {
			end = w.End
		}
	}
	return end
}

// Claim is one attribution with its evidence. Two independent sources are the
// bar for a claim that names a language or a producer.
type Claim struct {
	Slot       string    `json:"slot,omitempty"`
	Value      string    `json:"value"`
	Source     string    `json:"source"`
	ByteOffset int64     `json:"byte_offset"`
	Witnesses  []Witness `json:"witnesses,omitempty"`
	Conf       float64   `json:"conf,omitempty"`
}

// claim is the one-release shim: it still reports a zero-length witness at the
// offset it was given, and the engine decides whether a claim survived.
func (d *Digest) claim(value, source string, off int64) {
	for _, c := range d.Claims {
		if c.Value == value && c.Source == source {
			return
		}
	}
	d.Claims = append(d.Claims, Claim{Value: value, Source: source, ByteOffset: off})
	// The shim keeps the old source-as-witness rule for one release, so its
	// freeze keys on (site, source): a version loop is one source per class.
	d.witnessAt(callerSite(2)+"|"+source, Witness{Axis: "claim", Class: "claim:" + source, Value: value, Start: off, End: off})
}
