package main

import (
	"fmt"
	"strings"
)

// 178. uninstall_adb_package — y56: the shell exit code lies ("Failure […]",
// nil), so the status line decides; --user 0 only reverts the app to its
// factory version, hence the scope label.
func init() {
	registerOp(op{
		name:  "uninstall_adb_package",
		route: "Y",
		desc:  "adb shell pm uninstall --user 0 <pkg>; the status line decides, not the exit code (final.md y56)",
		needs: true,
		run:   opUninstallAdbPackage,
	})
}

type rt2UninstalledPackage struct {
	Package string `json:"package"`
	Scope   string `json:"scope"`
	Removed bool   `json:"removed"`
}

func opUninstallAdbPackage(target string) (any, error) {
	pkg := strings.TrimSpace(target)
	if pkg == "" {
		return nil, fmt.Errorf("uninstall_adb_package needs a package name")
	}
	if sk, err := rt2AdbReady("pm uninstall --user 0 <pkg>"); sk != nil || err != nil {
		return sk, err
	}
	out, sk, err := rt2AdbShell("pm", "uninstall", "--user", "0", pkg)
	if sk != nil || err != nil {
		return sk, err
	}
	status := rt2FirstLine(out)
	if status != "Success" {
		return nil, fmt.Errorf("pm uninstall --user 0 %s said %q", pkg, status)
	}
	return rt2UninstalledPackage{Package: pkg, Scope: "user0", Removed: true}, nil
}
