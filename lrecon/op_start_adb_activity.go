package main

import (
	"fmt"
	"strings"
)

// 170. start_adb_activity — y48: `am start -W -n <pkg>/<activity>`; a missing
// `Status:` line is a failure, not an empty status.
func init() {
	registerOp(op{
		name:  "start_adb_activity",
		route: "Y",
		desc:  "adb shell am start -W -n <pkg>/<activity>; target is the component (final.md y48)",
		needs: true,
		run:   opStartAdbActivity,
	})
}

type rt2AdbStart struct {
	Component string `json:"component"`
	Status    string `json:"status"`
	OK        bool   `json:"ok"`
}

func opStartAdbActivity(target string) (any, error) {
	component := strings.TrimSpace(target)
	pkg, act, ok := strings.Cut(component, "/")
	if !ok || pkg == "" || act == "" {
		return nil, fmt.Errorf("start_adb_activity target %q is not <pkg>/<activity>", component)
	}
	if sk, err := rt2AdbReady("am start -W -n <pkg>/<activity>"); sk != nil || err != nil {
		return sk, err
	}
	out, sk, err := rt2AdbShell("am", "start", "-W", "-n", component)
	if sk != nil || err != nil {
		return sk, err
	}
	status, err := rt2AMStatus(out)
	if err != nil {
		return nil, err
	}
	return rt2AdbStart{Component: component, Status: status, OK: status == "ok"}, nil
}
