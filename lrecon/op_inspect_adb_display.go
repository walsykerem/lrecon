package main

import (
	"fmt"
	"strings"
)

func init() {
	registerOp(op{
		name:  "inspect_adb_display",
		route: "Y",
		desc:  "physical/override screen size and density from `wm size; wm density` on the attached device",
		run:   inspectADBDisplay,
	})
}

type rtADBDisplay struct {
	PhysicalSize    string `json:"physical_size"`
	OverrideSize    string `json:"override_size,omitempty"`
	PhysicalDensity string `json:"physical_density"`
	OverrideDensity string `json:"override_density,omitempty"`
}

// inspectADBDisplay is §y y23: one shell call, no `dumpsys display`. An
// override line only appears when one is set, so absence is left absent.
func inspectADBDisplay(string) (any, error) {
	ctx, cancel := rtCtx()
	defer cancel()
	adb, sk := rtAdb()
	if sk != nil {
		return sk, nil
	}
	serial, sk, err := rtAdbSerial(ctx, adb, "wm size; wm density")
	if err != nil || sk != nil {
		return sk, err
	}
	out, err := rtAdbShell(ctx, adb, serial, "wm size; wm density")
	if err != nil {
		return nil, err
	}
	res := rtADBDisplay{}
	for _, l := range rtLines(out) {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "Physical size":
			res.PhysicalSize = v
		case "Override size":
			res.OverrideSize = v
		case "Physical density":
			res.PhysicalDensity = v
		case "Override density":
			res.OverrideDensity = v
		}
	}
	if res.PhysicalSize == "" || res.PhysicalDensity == "" {
		return nil, fmt.Errorf("wm size and wm density are not available on this device (no physical size/density line): %s", rtFirstLine(out))
	}
	return res, nil
}
