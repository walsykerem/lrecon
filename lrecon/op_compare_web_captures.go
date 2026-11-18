package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Items 186 and 187 both need a live page but compare in Go, so the capture is
// shared: 186 compares two request tables, 187 two screenshots of one page with
// a click in between (two identical captures would prove nothing — y62).

// Item 186. Two captures of the same flow, compared as sorted `method url status`
// lines. Bodies are not fetched, so the result says bodies:false rather than
// letting a status code stand in for content (y61).

func init() {
	registerOp(op{
		name:  "compare_web_captures",
		route: "Y",
		desc:  "capture the request table once more and diff it against the capture file already in <endpoint>=<dir>",
		needs: true,
		run:   opCompareWebCaptures,
	})
}

type captureDiff struct {
	Dir     string   `json:"dir"`
	Before  string   `json:"before,omitempty"`
	After   string   `json:"after,omitempty"`
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
	Same    int      `json:"same"`
	Bodies  bool     `json:"bodies"`
	Note    string   `json:"note,omitempty"`
}

func opCompareWebCaptures(target string) (any, error) {
	ep, arg, err := webTarget(target)
	if err != nil {
		return nil, err
	}
	if arg == "" {
		return nil, fmt.Errorf("no capture directory: pass <endpoint>=<dir> holding one earlier capture file")
	}
	entries, err := os.ReadDir(arg)
	if err != nil {
		return nil, err
	}
	out, sk, err := webRun("compare_web_captures", ep, webSpec{
		Mode:    "session",
		Steps:   []webStep{{Method: "Network.enable"}, {Method: "Page.enable"}},
		Collect: &webCollect{Ms: 1500, Prefixes: []string{"Network."}},
	})
	if sk != nil {
		return sk, nil
	}
	if err != nil {
		return nil, err
	}
	now := captureRequests(out.Events)
	if len(now) == 0 {
		return nil, fmt.Errorf("cdp %s: the live capture saw no requests; nothing to compare", ep)
	}
	diff := captureDiff{Dir: arg}
	var prior []webRequestRow
	baseName, baseIdx := "", 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		// capture-10.json sorts before capture-2.json, so the baseline is the
		// lowest numbered capture, never merely the first name ReadDir returns.
		n, ok := captureIndex(e.Name())
		if !ok {
			if baseName == "" {
				baseName = e.Name()
			}
			continue
		}
		if baseIdx == 0 || n < baseIdx {
			baseName, baseIdx = e.Name(), n
		}
	}
	if baseName != "" {
		var prev browserScenario
		if err := readJSONFile(filepath.Join(arg, baseName), &prev); err != nil {
			return nil, err
		}
		prior, diff.Before = prev.Requests, baseName
	}
	if prior == nil {
		name := nextCaptureName(arg, 1)
		if err := writeJSONFile(name, browserScenario{Mode: "attach", Requests: now, Count: len(now)}); err != nil {
			return nil, err
		}
		diff.After = filepath.Base(name)
		diff.Note = "no earlier capture in the directory: this run is now the baseline, run it again after the second run"
		return diff, nil
	}
	before := captureLines(prior)
	after := captureLines(now)
	diff.Same = twoPointer(before, after, &diff.Added, &diff.Removed)
	name := nextCaptureName(arg, baseIdx+1)
	if err := writeJSONFile(name, browserScenario{Mode: "attach", Requests: now, Count: len(now)}); err != nil {
		return nil, err
	}
	diff.After = filepath.Base(name)
	return diff, nil
}

// captureIndex reads the N in capture-N.json, the only names this op writes.
func captureIndex(name string) (int, bool) {
	if !strings.HasPrefix(name, "capture-") || !strings.HasSuffix(name, ".json") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(name, "capture-"), ".json"))
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// nextCaptureName starts at n and walks forward past any file already there, so
// a hole left by a removed capture is never overwritten by the next run.
func nextCaptureName(dir string, n int) string {
	for ; ; n++ {
		cand := filepath.Join(dir, fmt.Sprintf("capture-%d.json", n))
		if _, err := os.Stat(cand); os.IsNotExist(err) {
			return cand
		}
	}
}

// captureLines reduces a table to sorted comparable lines. The status is the
// whole of what is known: bodies were never fetched, so it is not a digest.
func captureLines(rows []webRequestRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, fmt.Sprintf("%s %s %d", r.Method, r.URL, r.Status))
	}
	sort.Strings(out)
	return out
}

// twoPointer walks two sorted line lists once, exactly like y61 describes.
func twoPointer(a, b []string, added, removed *[]string) int {
	i, j, same := 0, 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			same++
			i++
			j++
		case a[i] < b[j]:
			*removed = append(*removed, a[i])
			i++
		default:
			*added = append(*added, b[j])
			j++
		}
	}
	*removed = append(*removed, a[i:]...)
	*added = append(*added, b[j:]...)
	return same
}
