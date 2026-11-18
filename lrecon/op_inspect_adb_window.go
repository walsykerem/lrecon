package main

import (
	"fmt"
	"strings"
)

func init() {
	registerOp(op{
		name:  "inspect_adb_window",
		route: "Y",
		desc:  "current focus and focused app from `dumpsys window` on the attached device",
		run:   inspectADBWindow,
	})
}

type rtADBWindow struct {
	CurrentFocus string `json:"current_focus,omitempty"`
	FocusedApp   string `json:"focused_app,omitempty"`
	Windows      int    `json:"windows"`
}

// inspectADBWindow is §y y25: one `dumpsys window` call; screen metrics belong
// to inspect_adb_display and are not duplicated here.
func inspectADBWindow(string) (any, error) {
	ctx, cancel := rtCtx()
	defer cancel()
	adb, sk := rtAdb()
	if sk != nil {
		return sk, nil
	}
	serial, sk, err := rtAdbSerial(ctx, adb, "dumpsys window")
	if err != nil || sk != nil {
		return sk, err
	}
	out, err := rtAdbShell(ctx, adb, serial, "dumpsys window")
	if err != nil {
		return nil, err
	}
	res := rtADBWindow{}
	for _, l := range rtLines(out) {
		l = strings.TrimSpace(l)
		if v, ok := strings.CutPrefix(l, "mCurrentFocus="); ok {
			res.CurrentFocus = v
		}
		if v, ok := strings.CutPrefix(l, "mFocusedApp="); ok {
			res.FocusedApp = v
		}
		// Two shapes are in the wild: `Window{...}` and the newer
		// `Window #0 Window{...}` section header. Each window is one line,
		// so both prefixes count once and the same line cannot count twice.
		if strings.HasPrefix(l, "Window{") || strings.HasPrefix(l, "Window #") {
			res.Windows++
		}
	}
	if res.CurrentFocus == "" && res.FocusedApp == "" && res.Windows == 0 {
		return nil, fmt.Errorf("dumpsys window listed no windows: %s", rtFirstLine(out))
	}
	return res, nil
}
