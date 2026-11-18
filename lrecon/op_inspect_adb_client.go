package main

import (
	"fmt"
	"regexp"
	"strings"
)

func init() {
	registerOp(op{
		name:  "inspect_adb_client",
		route: "Y",
		desc:  "adb client version and build, plus the attached device table (`adb version`, `adb devices -l`)",
		run:   inspectADBClient,
	})
}

// `adb version` prints:
//
//	Android Debug Bridge version 1.0.41
//	Version 35.0.2-13114751
//	Installed as /Users/x/Library/Android/sdk/platform-tools/adb
var (
	rtADBVersionLine = regexp.MustCompile(`^Android Debug Bridge version (\S+)`)
	rtADBBuildLine   = regexp.MustCompile(`^Version (\S+)`)
	rtADBInstalled   = regexp.MustCompile(`^Installed as (\S+)`)
)

type rtADBClient struct {
	ClientVersion string     `json:"client_version,omitempty"`
	Build         string     `json:"build,omitempty"`
	Path          string     `json:"path,omitempty"`
	Devices       []rtDevice `json:"devices"`
}

// inspectADBClient is §y y21: the client version comes from the client binary,
// not from `host:version`, which reports whatever server happens to be running
// (Android Studio may have started a different one).
func inspectADBClient(string) (any, error) {
	ctx, cancel := rtCtx()
	defer cancel()
	adb, sk := rtAdb()
	if sk != nil {
		return sk, nil
	}
	out, err := rtRun(ctx, adb, "version")
	if err != nil {
		return nil, err
	}
	res := rtADBClient{}
	for _, l := range rtLines(out) {
		l = strings.TrimSpace(l)
		if m := rtADBVersionLine.FindStringSubmatch(l); m != nil {
			res.ClientVersion = m[1]
		}
		if m := rtADBBuildLine.FindStringSubmatch(l); m != nil {
			res.Build = m[1]
		}
		if m := rtADBInstalled.FindStringSubmatch(l); m != nil {
			res.Path = m[1]
		}
	}
	if res.ClientVersion == "" {
		return nil, fmt.Errorf("adb version is not available in the expected form (no version line): %s", rtFirstLine(out))
	}
	// The client inventory answers without a device; an empty table is the
	// observed truth, not a refusal.
	devs, err := rtRun(ctx, adb, "devices", "-l")
	if err != nil {
		return nil, err
	}
	res.Devices = rtParseDevices(devs)
	return res, nil
}
