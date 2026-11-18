package main

import "strings"

// 155. list_adb_services — y33: one `dumpsys -l`, not `service list`.
// `service list` was dropped because it is the same servicemanager set with a
// second command; the header the tool prints is the only non-service line.
func init() {
	registerOp(op{
		name:  "list_adb_services",
		route: "Y",
		desc:  "adb shell dumpsys -l: services the device's servicemanager is running (final.md y33)",
		run:   opListAdbServices,
	})
}

type rt2AdbService struct {
	Name string `json:"name"`
}

type rt2AdbServices struct {
	Services []rt2AdbService `json:"services"`
	Count    int             `json:"count"`
}

func opListAdbServices(string) (any, error) {
	if sk, err := rt2AdbReady("dumpsys -l"); sk != nil || err != nil {
		return sk, err
	}
	out, sk, err := rt2AdbShell("dumpsys", "-l")
	if sk != nil || err != nil {
		return sk, err
	}
	res := rt2AdbServices{Services: []rt2AdbService{}}
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasSuffix(line, "services:") {
			continue
		}
		res.Services = append(res.Services, rt2AdbService{Name: line})
	}
	res.Count = len(res.Services)
	return res, nil
}
