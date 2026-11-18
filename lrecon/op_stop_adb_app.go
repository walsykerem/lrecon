package main

import (
	"fmt"
	"strings"
)

// 175. stop_adb_app — y53: one `am force-stop <pkg>`. adb exits 0 on that, so
// an exit code is the whole answer and no output is expected.
func init() {
	registerOp(op{
		name:  "stop_adb_app",
		route: "Y",
		desc:  "adb shell am force-stop <pkg>; target is the package (final.md y53)",
		needs: true,
		run:   opStopAdbApp,
	})
}

type rt2StoppedApp struct {
	Package string   `json:"package"`
	Stopped bool     `json:"stopped"`
	Output  []string `json:"output"`
}

func opStopAdbApp(target string) (any, error) {
	pkg := strings.TrimSpace(target)
	if pkg == "" {
		return nil, fmt.Errorf("stop_adb_app needs a package name")
	}
	if sk, err := rt2AdbReady("am force-stop <pkg>"); sk != nil || err != nil {
		return sk, err
	}
	out, sk, err := rt2AdbShell("am", "force-stop", pkg)
	if sk != nil || err != nil {
		return sk, err
	}
	return rt2StoppedApp{Package: pkg, Stopped: true, Output: rt2Lines(out)}, nil
}
