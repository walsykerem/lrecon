package main

import (
	"regexp"
	"strconv"
	"strings"
)

// 176. trace_native_ui_action — y54: the only honest tap trace is evdev itself.
// `input` never touches /dev/input, so nothing in its output says what a tap
// did; `getevent -lt` does, and the op decodes each line to the decimal triple
// `sendevent` replays.
func init() {
	registerOp(op{
		name:  "trace_native_ui_action",
		route: "Y",
		desc:  "adb exec-out getevent -lt for one session: evdev events as device/type/code/value (final.md y54)",
		run:   opTraceNativeUIAction,
	})
}

// getevent -l prints both forms: the raw hex field and the decoded value after
// it, so the trailing decimal is optional and ignored. Key/switch/led values
// are words (DOWN/UP/REPEAT/ON/OFF), not hex: dropping them lost every
// BTN_TOUCH press in a tap trace.
var rt2GeteventLine = regexp.MustCompile(`^\[\s*([0-9.]+)\]\s+(\S+):\s+(\S+)\s+(\S+)\s+([0-9a-fA-F]+|[A-Z][A-Z0-9_]*)(?:\s+-?[0-9]+)?\s*$`)

type rt2UIEvent struct {
	At     string `json:"at"`
	Device string `json:"device"`
	Type   string `json:"type"`
	Code   string `json:"code"`
	Value  int64  `json:"value"`
}

type rt2UITrace struct {
	Events   []rt2UIEvent `json:"events"`
	Count    int          `json:"count"`
	Unparsed int          `json:"unparsed"`
	Killed   bool         `json:"killed"`
	Note     string       `json:"note,omitempty"`
}

// rt2GeteventHeader reports the device description getevent -l prints once at
// start. Those lines are not events, so counting them as parse failures made a
// quiet device look like a parser bug.
func rt2GeteventHeader(line string) bool {
	t := strings.TrimSpace(line)
	for _, p := range []string{"add device ", "name:", "events:", "KEY (", "ABS (", "REL (", "MSC (", "SW  (", "LED (", "SND (", "input props", "position:"} {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

// rt2EventValue reads getevent's value field: a hex number for EV_ABS/EV_REL and
// a word for EV_KEY/EV_SW/EV_LED.
func rt2EventValue(s string) (int64, bool) {
	switch s {
	case "UP", "OFF":
		return 0, true
	case "DOWN", "ON":
		return 1, true
	case "REPEAT":
		return 2, true
	}
	v, err := strconv.ParseInt(s, 16, 64)
	return v, err == nil
}

func opTraceNativeUIAction(string) (any, error) {
	if sk, err := rt2AdbReady(); sk != nil || err != nil {
		return sk, err
	}
	out, killed, sk, err := rt2RunSession("adb", rt2AdbAlt, "exec-out", "getevent", "-lt")
	if sk != nil || err != nil {
		return sk, err
	}
	res := rt2UITrace{Killed: killed}
	for line := range strings.SplitSeq(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		m := rt2GeteventLine.FindStringSubmatch(line)
		if m == nil {
			if !rt2GeteventHeader(line) {
				res.Unparsed++
			}
			continue
		}
		v, ok := rt2EventValue(m[5])
		if !ok {
			res.Unparsed++
			continue
		}
		res.Events = append(res.Events, rt2UIEvent{
			At:     m[1],
			Device: strings.TrimSuffix(m[2], ":"),
			Type:   m[3],
			Code:   m[4],
			Value:  v,
		})
	}
	res.Count = len(res.Events)
	if res.Count == 0 {
		// The emulator injects input above evdev, and a host-side tap never
		// reaches /dev/input, so "no events" is a fact worth stating.
		res.Note = "no evdev event in the window: either nothing happened on the device, or the input was injected above evdev (the Android emulator does this); on hardware, run the same op while touching the screen"
	}
	return res, nil
}
