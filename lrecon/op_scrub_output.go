package main

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// scrubFinding names where a secret-shaped run is, never what it says: the
// offset, the pattern id and the length are the whole answer, so a scrub report
// can be pasted into an issue without leaking the token it found.
type scrubFinding struct {
	Offset  int    `json:"offset"`
	Pattern string `json:"pattern"`
	Length  int    `json:"length"`
}

type scrubResult struct {
	Scrubbed int            `json:"scrubbed"`
	Findings []scrubFinding `json:"findings"`
	Clean    bool           `json:"clean"`
}

func init() {
	registerOp(op{
		name:  "scrub_output",
		route: "L",
		needs: false,
		desc:  "Scan a file (or stdin when the argument is \"-\") for secret-shaped runs and report only offset, pattern id and length; matched bytes are never printed.",
		run:   runScrubOutput,
	})
}

var scrubPatterns = []struct {
	id string
	re *regexp.Regexp
}{
	{"aws-akia", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"github-ghp", regexp.MustCompile(`ghp_[A-Za-z0-9]{20,}`)},
	{"openai-sk", regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`)},
	{"pem-private-key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
}

// scrubEntropyWindow is the run the entropy gate measures, and scrubEntropyBits
// the Shannon entropy a random 40-byte token clears (a 64-symbol alphabet sits
// near 5.5 bits/byte; prose over the same window stays under 4.5).
const (
	scrubEntropyWindow = 40
	scrubEntropyBits   = 4.5
)

// runScrubOutput reads the target once and scans it. "-" is stdin because the
// point of a scrubber is to check text that never touched the disk.
func runScrubOutput(path string) (any, error) {
	if path == "" {
		return nil, fmt.Errorf("scrub_output needs a target path, or \"-\" to scan stdin")
	}
	var b []byte
	var err error
	if path == "-" {
		// ponytail: stdin is read whole and capped; a streaming scanner would
		// need overlap windows, upgrade if stdin ever exceeds the 256 MiB cap.
		b, err = io.ReadAll(io.LimitReader(os.Stdin, opMaxFile+1))
		if err == nil && len(b) > opMaxFile {
			return skipf("stdin is over the %d-byte cap; scrub_output scans whole input", opMaxFile), nil
		}
	} else {
		b, err = opRead(path, opMaxFile)
		if err != nil && strings.Contains(err.Error(), "over the ") {
			return skipf("%v; scrub_output scans whole files", err), nil
		}
	}
	if err != nil {
		return nil, err
	}
	return scrubBytes(b), nil
}

// scrubRunByte is the token alphabet for the entropy gate: one printable,
// non-space byte.
func scrubRunByte(c byte) bool { return c > 0x20 && c < 0x7f }

// scrubBytes is the scanner itself: regex hits first, then the entropy gate on
// runs the regexes did not already claim. Runs break on whitespace, so prose is
// never a 40-byte token and binary noise is not printable.
func scrubBytes(b []byte) scrubResult {
	findings := []scrubFinding{}
	for _, p := range scrubPatterns {
		for _, m := range p.re.FindAllIndex(b, -1) {
			findings = append(findings, scrubFinding{Offset: m[0], Pattern: p.id, Length: m[1] - m[0]})
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Offset < findings[j].Offset })
	for off := 0; off < len(b); {
		if !scrubRunByte(b[off]) {
			off++
			continue
		}
		end := off
		for end < len(b) && scrubRunByte(b[end]) {
			end++
		}
		if n := end - off; n >= scrubEntropyWindow && !scrubClaimed(findings, off, end) {
			high := false
			for _, h := range blockEntropy(b[off:end], scrubEntropyWindow) {
				if h >= scrubEntropyBits {
					high = true
					break
				}
			}
			if high {
				findings = append(findings, scrubFinding{Offset: off, Pattern: "entropy-40", Length: n})
			}
		}
		off = end
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Offset < findings[j].Offset })
	return scrubResult{Scrubbed: len(findings), Findings: findings, Clean: len(findings) == 0}
}

// scrubClaimed reports whether a regex finding already covers part of [start,end).
func scrubClaimed(findings []scrubFinding, start, end int) bool {
	for _, f := range findings {
		if f.Offset < end && start < f.Offset+f.Length {
			return true
		}
	}
	return false
}
