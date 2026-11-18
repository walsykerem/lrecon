package main

import (
	"regexp"
	"strconv"
	"strings"
)

// 164. read_adb_logcat — y42: one dump, `logcat -d -t 2000` (threadtime is the
// default format, `-t` already implies `-d`, and gadb's Logcat() is gone because
// it hard-codes `shell:logcat` and takes no arguments).
func init() {
	registerOp(op{
		name:  "read_adb_logcat",
		route: "Y",
		desc:  "adb shell logcat -d -t 2000 parsed from threadtime lines (final.md y42)",
		run:   opReadAdbLogcat,
	})
}

var rt2LogcatLine = regexp.MustCompile(`^\s*(\d\d-\d\d\s+\d\d:\d\d:\d\d\.\d+)\s+(\d+)\s+(\d+)\s+([VDIWEFAS])\s+([^:]+?):\s?(.*)$`)

type rt2LogcatEntry struct {
	Time  string `json:"time"`
	PID   int    `json:"pid"`
	TID   int    `json:"tid"`
	Level string `json:"level"`
	Tag   string `json:"tag"`
	Msg   string `json:"msg"`
}

type rt2Logcat struct {
	Entries  []rt2LogcatEntry `json:"entries"`
	Count    int              `json:"count"`
	Unparsed int              `json:"unparsed"`
}

func opReadAdbLogcat(string) (any, error) {
	if sk, err := rt2AdbReady("logcat -d -t 2000"); sk != nil || err != nil {
		return sk, err
	}
	out, sk, err := rt2AdbShell("logcat", "-d", "-t", "2000")
	if sk != nil || err != nil {
		return sk, err
	}
	res := rt2Logcat{}
	for line := range strings.SplitSeq(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		m := rt2LogcatLine.FindStringSubmatch(line)
		if m == nil {
			res.Unparsed++
			continue
		}
		pid, pidErr := strconv.Atoi(m[2])
		tid, tidErr := strconv.Atoi(m[3])
		if pidErr != nil || tidErr != nil {
			res.Unparsed++
			continue
		}
		res.Entries = append(res.Entries, rt2LogcatEntry{
			Time:  strings.Join(strings.Fields(m[1]), " "),
			PID:   pid,
			TID:   tid,
			Level: m[4],
			Tag:   strings.TrimSpace(m[5]),
			Msg:   m[6],
		})
	}
	res.Count = len(res.Entries)
	return res, nil
}
