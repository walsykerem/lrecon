package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Item 192. A HAR 1.2 export is what a browser or an external capture tool wrote
// for one page load: no endpoint is needed, the timing and size of each request
// is already in the file.

func init() {
	registerOp(op{
		name:  "inspect_web_network_capture",
		route: "L",
		desc:  "read a HAR 1.2 capture: per-entry method, url, status, duration and size, plus the host table",
		needs: true,
		run:   opInspectWebNetworkCapture,
	})
}

const maxHAREntries = 2000

type harFile struct {
	Log struct {
		Version string `json:"version"`
		Creator struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"creator"`
		Entries []struct {
			StartedDateTime string  `json:"startedDateTime"`
			Time            float64 `json:"time"`
			Request         struct {
				Method string `json:"method"`
				URL    string `json:"url"`
			} `json:"request"`
			Response struct {
				Status  int `json:"status"`
				Content struct {
					Size     int64  `json:"size"`
					MimeType string `json:"mimeType"`
				} `json:"content"`
				BodySize int64 `json:"bodySize"`
			} `json:"response"`
		} `json:"entries"`
	} `json:"log"`
}

type harEntryRow struct {
	Method   string  `json:"method"`
	URL      string  `json:"url"`
	Status   int     `json:"status"`
	Ms       float64 `json:"ms"`
	Bytes    int64   `json:"bytes"`
	MimeType string  `json:"mime_type"`
}

type harSummary struct {
	Version   string        `json:"version"`
	Creator   string        `json:"creator"`
	Entries   int           `json:"entries"`
	TotalMs   float64       `json:"total_ms"`
	TotalSize int64         `json:"total_bytes"`
	Hosts     []string      `json:"hosts"`
	Requests  []harEntryRow `json:"requests"`
	Truncated bool          `json:"truncated"`
}

func opInspectWebNetworkCapture(path string) (any, error) {
	b, err := opRead(path, opMaxFile)
	if err != nil {
		return nil, err
	}
	var har harFile
	if err := json.Unmarshal(b, &har); err != nil {
		return nil, fmt.Errorf("%s is not HAR JSON: %v", path, err)
	}
	if har.Log.Version == "" {
		return nil, fmt.Errorf("%s has no log.version: not a HAR 1.2 capture", path)
	}
	out := harSummary{
		Version: har.Log.Version,
		Creator: har.Log.Creator.Name + " " + har.Log.Creator.Version,
		Entries: len(har.Log.Entries),
	}
	hosts := map[string]bool{}
	for i, e := range har.Log.Entries {
		size := e.Response.Content.Size
		if size == 0 {
			size = e.Response.BodySize
		}
		out.TotalMs += e.Time
		out.TotalSize += size
		row := harEntryRow{
			Method:   e.Request.Method,
			URL:      e.Request.URL,
			Status:   e.Response.Status,
			Ms:       e.Time,
			Bytes:    size,
			MimeType: e.Response.Content.MimeType,
		}
		if i < maxHAREntries {
			out.Requests = append(out.Requests, row)
		} else {
			out.Truncated = true
		}
		hosts[urlHost(e.Request.URL)] = true
	}
	for h := range hosts {
		out.Hosts = append(out.Hosts, h)
	}
	sort.Strings(out.Hosts)
	return out, nil
}

// urlHost is the host of one absolute URL without pulling a parser in: the
// capture already stores absolute URLs, and a malformed one keeps its text.
func urlHost(u string) string {
	_, after, ok := strings.Cut(u, "://")
	if !ok {
		return u
	}
	rest := after
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		return rest[:j]
	}
	return rest
}
