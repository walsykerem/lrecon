package main

import (
	"fmt"
	"strings"
)

// 165. read_adb_setting — y43: `settings get <namespace> <key>`; a whole
// namespace is `settings list <ns>`, which this op does not pretend to do.
func init() {
	registerOp(op{
		name:  "read_adb_setting",
		route: "Y",
		desc:  "adb shell settings get <system|secure|global> <key>; target is <namespace>:<key> or just <key> (final.md y43)",
		needs: true,
		run:   opReadAdbSetting,
	})
}

type rt2AdbSetting struct {
	Namespace string  `json:"namespace"`
	Key       string  `json:"key"`
	Value     *string `json:"value"`
	Set       bool    `json:"set"`
}

func opReadAdbSetting(target string) (any, error) {
	ns, key := "system", strings.TrimSpace(target)
	if a, b, ok := strings.Cut(key, ":"); ok {
		ns, key = strings.TrimSpace(a), strings.TrimSpace(b)
	}
	switch ns {
	case "system", "secure", "global":
	default:
		return nil, fmt.Errorf("settings namespace %q is not system, secure or global", ns)
	}
	if key == "" {
		return nil, fmt.Errorf("read_adb_setting needs an argument: a setting key after %q", ns)
	}
	if sk, err := rt2AdbReady("settings get <namespace> <key>"); sk != nil || err != nil {
		return sk, err
	}
	out, sk, err := rt2AdbShell("settings", "get", ns, key)
	if sk != nil || err != nil {
		return sk, err
	}
	v := strings.TrimSpace(out)
	res := rt2AdbSetting{Namespace: ns, Key: key}
	if v != "" && v != "null" {
		res.Value = &v
		res.Set = true
	}
	return res, nil
}
