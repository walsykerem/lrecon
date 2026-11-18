package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// metaCrashImage is one binary the crash report says was loaded.
type metaCrashImage struct {
	Name  string `json:"name"`
	UUID  string `json:"uuid"`
	Arch  string `json:"arch"`
	Match bool   `json:"match"`
}

func metaNormUUID(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), "-", ""))
}

// metaCrashImages reads the usedImages list out of an Apple .ips report: the
// file is a header JSON object followed by the report JSON object.
func metaCrashImages(b []byte) ([]metaCrashImage, map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	var report map[string]any
	if err := dec.Decode(&report); err != nil {
		return nil, nil, fmt.Errorf("not a JSON crash report: %v", err)
	}
	if dec.More() {
		var body map[string]any
		if err := dec.Decode(&body); err == nil {
			report = body
		}
	}
	raw, _ := report["usedImages"].([]any)
	var out []metaCrashImage
	for _, r := range raw {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		img := metaCrashImage{Name: metaAnyString(m["name"]), UUID: metaAnyString(m["uuid"]), Arch: metaAnyString(m["arch"])}
		out = append(out, img)
	}
	return out, report, nil
}

func metaAnyString(v any) string {
	s, _ := v.(string)
	return s
}

func init() {
	registerOp(op{
		name:  "correlate_static_and_runtime",
		route: "L",
		needs: true,
		desc:  "Join a static probe with a runtime crash report: parse the .ips usedImages, match their uuids against the probed image uuid and name each match or mismatch.",
		run:   runCorrelateStaticRuntime,
	})
}

// metaStaticImages lists the uuids a probed image carries. A fat Mach-O has
// one uuid per slice and no top-level uuid, so the slice lines are the only
// place they survive; a thin image uses the digest uuid directly.
func metaStaticImages(d Digest) []metaCrashImage {
	var out []metaCrashImage
	for _, line := range d.SliceInfo {
		parts := strings.Fields(line)
		img := metaCrashImage{}
		if len(parts) > 0 {
			img.Arch = parts[0]
		}
		for i := 0; i+1 < len(parts); i++ {
			if parts[i] == "uuid" {
				img.UUID = parts[i+1]
				break
			}
		}
		if img.UUID != "" {
			out = append(out, img)
		}
	}
	if len(out) == 0 && d.UUID != "" {
		out = append(out, metaCrashImage{UUID: d.UUID})
	}
	return out
}

func runCorrelateStaticRuntime(path string) (any, error) {
	job, err := metaLoadJob(path)
	if err != nil {
		return nil, err
	}
	target := job.File
	if target == "" {
		target = path
	}
	crash := job.Crash
	if crash == "" {
		crash = job.New
	}
	if crash == "" {
		return nil, fmt.Errorf("correlate_static_and_runtime: job needs \"crash\" (an .ips path) next to \"file\"")
	}
	b, err := os.ReadFile(crash)
	if err != nil {
		return nil, err
	}
	images, report, err := metaCrashImages(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", crash, err)
	}
	d, err := loadDigest(target)
	if err != nil {
		return nil, err
	}
	statics := metaStaticImages(d)
	static := map[string]any{"file": target, "uuid": d.UUID, "kind": d.Kind, "minos": d.MinOS, "images": statics}
	want := map[string]string{}
	for _, s := range statics {
		want[metaNormUUID(s.UUID)] = s.Arch
	}
	if len(want) == 0 {
		return nil, fmt.Errorf("correlate_static_and_runtime: %s carries no uuid to correlate (kind %s)", target, d.Kind)
	}
	matches, mismatches := 0, 0
	for i := range images {
		_, images[i].Match = want[metaNormUUID(images[i].UUID)]
		if images[i].Match {
			matches++
		} else {
			mismatches++
		}
	}
	res := map[string]any{
		"static":     static,
		"runtime":    map[string]any{"crash": crash, "proc": metaAnyString(report["procName"]), "os": metaAnyString(report["osVersion"]), "images": images, "image_count": len(images)},
		"matches":    matches,
		"mismatches": mismatches,
	}
	switch {
	case matches == 1:
		res["verdict"] = "static image matches the crashing image uuid"
	case matches > 1:
		res["verdict"] = fmt.Sprintf("%d loaded images carry the probed uuid (dyld shared cache copies)", matches)
	case len(images) == 0:
		res["verdict"] = "crash report lists no usedImages"
	default:
		res["verdict"] = "crash report was produced by a different build; uuids do not match"
	}
	return res, nil
}
