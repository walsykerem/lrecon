package main

import (
	"fmt"
	"strings"
)

func init() {
	registerOp(op{
		name:  "inspect_adb_package",
		route: "Y",
		desc:  "version and requested permissions of one installed package (target = package name; `dumpsys package <pkg>`)",
		needs: true,
		run:   inspectADBPackage,
	})
}

type rtADBPackage struct {
	Package     string   `json:"package"`
	State       string   `json:"state"`
	VersionName string   `json:"version_name,omitempty"`
	VersionCode string   `json:"version_code,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// inspectADBPackage is §y y24: `dumpsys package` exits 0 for an unknown package
// too, so the `Unable to find package:` sentinel is the only honest signal.
func inspectADBPackage(pkg string) (any, error) {
	ctx, cancel := rtCtx()
	defer cancel()
	adb, sk := rtAdb()
	if sk != nil {
		return sk, nil
	}
	serial, sk, err := rtAdbSerial(ctx, adb, "dumpsys package <pkg>")
	if err != nil || sk != nil {
		return sk, err
	}
	out, err := rtAdbShell(ctx, adb, serial, "dumpsys", "package", pkg)
	if err != nil {
		return nil, err
	}
	if strings.Contains(out, "Unable to find package: "+pkg) {
		return rtADBPackage{Package: pkg, State: "not-installed"}, nil
	}
	// `dumpsys package <name>` exits 0 and prints the WHOLE database for a name
	// it does not recognise, so the first versionName= in that dump can belong to
	// any package: values come from the `Package [<pkg>]` section only, and no
	// such section means the device answered for nothing.
	hdr := "Package [" + pkg + "]"
	seen := false
	res := rtADBPackage{Package: pkg, State: "installed"}
	inPerms := false
	for _, l := range rtLines(out) {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "Package [") {
			seen = strings.HasPrefix(l, hdr)
			inPerms = false
			continue
		}
		if !seen {
			continue
		}
		if v, ok := strings.CutPrefix(l, "versionName="); ok {
			res.VersionName = v
		}
		if v, ok := strings.CutPrefix(l, "versionCode="); ok {
			if f := strings.Fields(v); len(f) > 0 {
				res.VersionCode = f[0]
			}
		}
		if l == "requested permissions:" {
			inPerms = true
			continue
		}
		if inPerms {
			// The section ends at the next `key:` or an empty line that rtLines
			// already dropped; a permission line is a bare dotted name.
			if strings.HasSuffix(l, ":") || strings.Contains(l, " ") {
				inPerms = false
				continue
			}
			res.Permissions = append(res.Permissions, l)
		}
	}
	if res.VersionName == "" && res.VersionCode == "" {
		if !seen {
			return nil, fmt.Errorf("dumpsys package %s printed no %s section: not a package name this device knows (%d bytes of dump)", pkg, hdr, len(out))
		}
		return nil, fmt.Errorf("dumpsys package %s printed neither versionName nor versionCode: not a package dump", pkg)
	}
	return res, nil
}
