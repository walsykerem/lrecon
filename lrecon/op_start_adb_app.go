package main

import (
	"fmt"
	"strings"
)

// 171. start_adb_app — y49: LAUNCHER resolution and a monkey fallback were
// dropped; `am` resolves the implicit intent itself, and `-W` reports
// `Status: ok|timeout`, which is the answer.
func init() {
	registerOp(op{
		name:  "start_adb_app",
		route: "Y",
		desc:  "adb shell am start -W -a MAIN -c LAUNCHER -p <pkg>; target is the package (final.md y49)",
		needs: true,
		run:   opStartAdbApp,
	})
}

type rt2StartedApp struct {
	Package string `json:"package"`
	Status  string `json:"status"`
	OK      bool   `json:"ok"`
}

func opStartAdbApp(target string) (any, error) {
	pkg := strings.TrimSpace(target)
	if pkg == "" {
		return nil, fmt.Errorf("start_adb_app needs a package name")
	}
	if sk, err := rt2AdbReady("am start -W -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -p <pkg>"); sk != nil || err != nil {
		return sk, err
	}
	out, sk, err := rt2AdbShell("am", "start", "-W",
		"-a", "android.intent.action.MAIN",
		"-c", "android.intent.category.LAUNCHER",
		"-p", pkg)
	if sk != nil || err != nil {
		return sk, err
	}
	status, err := rt2AMStatus(out)
	if err != nil {
		return nil, err
	}
	return rt2StartedApp{Package: pkg, Status: status, OK: status == "ok"}, nil
}
