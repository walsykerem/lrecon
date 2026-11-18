package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func init() {
	registerOp(op{
		name:  "inspect_apple_ips",
		route: "L",
		desc:  "header fields of an Apple .ips crash report (app_version, os_version, bug_type, timestamp, name); no live process needed",
		needs: true,
		run:   inspectAppleIPS,
	})
}

type rtAppleIPS struct {
	AppVersion string `json:"app_version,omitempty"`
	OSVersion  string `json:"os_version,omitempty"`
	BugType    string `json:"bug_type,omitempty"`
	Timestamp  string `json:"timestamp,omitempty"`
	Name       string `json:"name,omitempty"`
	BodyParsed bool   `json:"body_parsed"`
}

// inspectAppleIPS is §y item 146: an .ips is a header JSON line, then a body
// JSON object. Both are tried, and a file that is only the header still
// answers; the body flag says which shape was seen instead of guessing.
func inspectAppleIPS(path string) (any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var res rtAppleIPS
	var header map[string]any
	if err := json.Unmarshal(b, &header); err == nil {
		res.BodyParsed = true
	} else {
		first, rest, _ := strings.Cut(string(b), "\n")
		if err := json.Unmarshal([]byte(first), &header); err != nil {
			return nil, fmt.Errorf("%s is not an .ips report: header line is not JSON: %w", path, err)
		}
		var body any
		res.BodyParsed = json.Unmarshal([]byte(rest), &body) == nil
	}
	if _, ok := header["bug_type"]; !ok {
		return nil, fmt.Errorf("%s has no bug_type: not an .ips header", path)
	}
	res.BugType = rtJSONString(header["bug_type"])
	res.AppVersion = rtJSONString(header["app_version"])
	res.OSVersion = rtJSONString(header["os_version"])
	res.Timestamp = rtJSONString(header["timestamp"])
	res.Name = rtJSONString(header["name"])
	return res, nil
}

func rtJSONString(v any) string {
	s, _ := v.(string)
	return s
}
