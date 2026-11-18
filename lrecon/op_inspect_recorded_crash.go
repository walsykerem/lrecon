package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// final.md 35: inspect_recorded_crash.
func init() {
	registerOp(op{
		name:  "inspect_recorded_crash",
		route: "L",
		desc:  "Apple .ips crash report: JSON header line + JSON body line, with exception, faulting thread and every frame's image offset and symbol",
		needs: true,
		run:   runInspectRecordedCrash,
	})
}

type netcCrashFrame struct {
	ImageIndex  int    `json:"image_index"`
	Image       string `json:"image,omitempty"`
	ImageOffset int64  `json:"image_offset"`
	Offset      string `json:"offset_hex"`
	Address     string `json:"address,omitempty"`
	Symbol      string `json:"symbol,omitempty"`
	SymbolLoc   int64  `json:"symbol_location,omitempty"`
	Source      string `json:"source,omitempty"`
	SourceLine  int64  `json:"source_line,omitempty"`
}

type netcCrashThread struct {
	Index     int              `json:"index"`
	ID        int64            `json:"id,omitempty"`
	Name      string           `json:"name,omitempty"`
	Queue     string           `json:"queue,omitempty"`
	Triggered bool             `json:"triggered"`
	Frames    []netcCrashFrame `json:"frames"`
}

type netcCrashImage struct {
	Index int    `json:"index"`
	Name  string `json:"name,omitempty"`
	Path  string `json:"path,omitempty"`
	Base  uint64 `json:"base"`
	UUID  string `json:"uuid,omitempty"`
	Arch  string `json:"arch,omitempty"`
}

type netcCrashException struct {
	Type   string `json:"type"`
	Signal string `json:"signal,omitempty"`
	Codes  string `json:"codes,omitempty"`
}

func runInspectRecordedCrash(path string) (any, error) {
	b, err := opRead(path, opMaxFile)
	if err != nil {
		return nil, err
	}
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	// Apple puts a one-line JSON header first; the body is the rest of the
	// file, which is pretty-printed in real reports.
	before, after, ok := bytes.Cut(b, []byte{'\n'})
	if !ok {
		return nil, fmt.Errorf("%s has one JSON line; an Apple .ips carries the header on line 1 and the crash body from line 2 on", path)
	}
	headerLine := bytes.TrimSpace(before)
	bodyLine := bytes.TrimSpace(after)
	if len(headerLine) == 0 || len(bodyLine) == 0 {
		return nil, fmt.Errorf("%s has an empty header or an empty body; an Apple .ips needs both", path)
	}
	dec := func(name string, line []byte, into any) error {
		d := json.NewDecoder(bytes.NewReader(line))
		d.UseNumber()
		if err := d.Decode(into); err != nil {
			return fmt.Errorf("%s: line %s is not JSON: %v", path, name, err)
		}
		return nil
	}
	var header map[string]any
	var body map[string]any
	if err := dec("1 (header)", headerLine, &header); err != nil {
		return nil, err
	}
	if err := dec("2 (body)", bodyLine, &body); err != nil {
		return nil, err
	}

	images := netcCrashImages(body)
	exc, okExc := netcCrashExceptionOf(body["exception"])
	threads, triggered, okThreads := netcCrashThreads(body["threads"], images)
	faulting, hasFault := netcInt(body["faultingThread"])
	if !okThreads && !okExc {
		return nil, fmt.Errorf("%s: body carries neither an exception object nor a threads array, so it is not a crash report", path)
	}
	if !hasFault {
		faulting = -1
	}
	out := map[string]any{
		"header":           header,
		"app":              netcFirstOf(header, "app_name", "name"),
		"bundle_id":        netcFirstOf(header, "bundleID", "bundle_id"),
		"app_version":      netcFirstOf(header, "app_version"),
		"build_version":    netcFirstOf(header, "build_version"),
		"os_version":       netcFirstOf(header, "os_version"),
		"timestamp":        netcFirstOf(header, "timestamp"),
		"incident_id":      netcFirstOf(header, "incident_id"),
		"faulting_thread":  faulting,
		"triggered_thread": triggered,
		"threads":          threads,
		"images":           images,
	}
	if okExc {
		out["exception"] = exc
	}
	// Both gaps can hold at once, so they share one note instead of the second
	// one silently replacing the first.
	var notes []string
	if !okExc {
		notes = append(notes, "body has threads but no exception object")
	}
	if !hasFault {
		notes = append(notes, "body has no faultingThread index; the triggered frame is at threads[].triggered")
	}
	if len(notes) > 0 {
		out["note"] = strings.Join(notes, "; ")
	}
	return out, nil
}

func netcFirstOf(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func netcInt(v any) (int, bool) {
	switch x := v.(type) {
	case json.Number:
		n, err := x.Int64()
		return int(n), err == nil
	case float64:
		return int(x), true
	case string:
		n, err := strconv.ParseInt(x, 10, 64)
		return int(n), err == nil
	}
	return 0, false
}

func netcInt64(v any) (int64, bool) {
	switch x := v.(type) {
	case json.Number:
		n, err := x.Int64()
		return n, err == nil
	case float64:
		return int64(x), true
	case string:
		n, err := strconv.ParseInt(x, 0, 64)
		return n, err == nil
	}
	return 0, false
}

func netcStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func netcCrashExceptionOf(v any) (netcCrashException, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return netcCrashException{}, false
	}
	e := netcCrashException{
		Type:   netcStr(m, "type"),
		Signal: netcStr(m, "signal"),
		Codes:  netcStr(m, "codes"),
	}
	if e.Type == "" && e.Signal == "" && e.Codes == "" {
		return e, false
	}
	return e, true
}

// netcCrashImages indexes usedImages by their position, which is what a frame's
// imageIndex refers to.
func netcCrashImages(body map[string]any) []netcCrashImage {
	raw, _ := body["usedImages"].([]any)
	out := make([]netcCrashImage, 0, len(raw))
	for i, v := range raw {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		img := netcCrashImage{
			Index: i,
			Name:  netcStr(m, "name"),
			Path:  netcStr(m, "path"),
			UUID:  netcStr(m, "uuid"),
			Arch:  netcStr(m, "arch"),
		}
		if n, ok := netcInt64(m["base"]); ok && n > 0 {
			img.Base = uint64(n)
		}
		if img.Name == "" {
			img.Name = lastPathPart(img.Path)
		}
		out = append(out, img)
	}
	return out
}

func lastPathPart(p string) string {
	if i := strings.LastIndexByte(strings.TrimSuffix(p, "/"), '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func netcCrashThreads(v any, images []netcCrashImage) ([]netcCrashThread, int, bool) {
	raw, ok := v.([]any)
	if !ok {
		return nil, -1, false
	}
	triggered := -1
	out := make([]netcCrashThread, 0, len(raw))
	for i, tv := range raw {
		m, ok := tv.(map[string]any)
		if !ok {
			continue
		}
		t := netcCrashThread{Index: i, Name: netcStr(m, "name"), Queue: netcStr(m, "queue")}
		if n, ok := netcInt64(m["id"]); ok {
			t.ID = n
		}
		if b, ok := m["triggered"].(bool); ok {
			t.Triggered = b
			if b && triggered < 0 {
				triggered = i
			}
		}
		frames, _ := m["frames"].([]any)
		t.Frames = make([]netcCrashFrame, 0, len(frames))
		for _, fv := range frames {
			fm, ok := fv.(map[string]any)
			if !ok {
				continue
			}
			f := netcCrashFrame{
				Symbol: netcStr(fm, "symbol"),
				Source: netcStr(fm, "sourceFile", "source_file"),
			}
			if n, ok := netcInt64(fm["imageIndex"]); ok {
				f.ImageIndex = int(n)
			} else if n, ok := netcInt64(fm["image_index"]); ok {
				f.ImageIndex = int(n)
			}
			if n, ok := netcInt64(fm["imageOffset"]); ok {
				f.ImageOffset = n
			} else if n, ok := netcInt64(fm["image_offset"]); ok {
				f.ImageOffset = n
			}
			if n, ok := netcInt64(fm["symbolLocation"]); ok {
				f.SymbolLoc = n
			}
			if n, ok := netcInt64(fm["sourceLine"]); ok {
				f.SourceLine = n
			}
			f.Offset = fmt.Sprintf("%#x", f.ImageOffset)
			if f.ImageIndex >= 0 && f.ImageIndex < len(images) {
				f.Image = images[f.ImageIndex].Name
				if images[f.ImageIndex].Base != 0 {
					f.Address = fmt.Sprintf("%#x", images[f.ImageIndex].Base+uint64(f.ImageOffset))
				}
			}
			t.Frames = append(t.Frames, f)
		}
		out = append(out, t)
	}
	return out, triggered, true
}
