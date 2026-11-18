package main

import "strings"

func init() {
	registerOp(op{
		name:  "inspect_adb_device",
		route: "Y",
		desc:  "model, sdk, build fingerprint and ro.debuggable of the attached device (one getprop call)",
		run:   inspectADBDevice,
	})
}

type rtADBDeviceProps struct {
	Serial      string `json:"serial"`
	Model       string `json:"model"`
	SDK         string `json:"sdk"`
	Fingerprint string `json:"fingerprint"`
	Debuggable  string `json:"debuggable"`
}

// inspectADBDevice is §y y22: the four props §y names, read in one shell call
// so they describe the same moment.
func inspectADBDevice(string) (any, error) {
	ctx, cancel := rtCtx()
	defer cancel()
	adb, sk := rtAdb()
	if sk != nil {
		return sk, nil
	}
	serial, sk, err := rtAdbSerial(ctx, adb, "getprop ro.product.model …")
	if err != nil || sk != nil {
		return sk, err
	}
	out, err := rtAdbShell(ctx, adb, serial,
		"getprop ro.product.model; getprop ro.build.version.sdk; getprop ro.build.fingerprint; getprop ro.debuggable")
	if err != nil {
		return nil, err
	}
	// Positional, so empty props keep their slot: rtLines drops blanks, which
	// would shift ro.debuggable into the fingerprint field.
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	for len(lines) < 4 {
		lines = append(lines, "")
	}
	return rtADBDeviceProps{
		Serial:      serial,
		Model:       strings.TrimSpace(lines[0]),
		SDK:         strings.TrimSpace(lines[1]),
		Fingerprint: strings.TrimSpace(lines[2]),
		Debuggable:  strings.TrimSpace(lines[3]),
	}, nil
}
