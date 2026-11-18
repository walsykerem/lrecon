package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// An op is one inventory item: a named operation on one artifact. Every op
// lives in its own file and registers itself from init(), so 229 items never
// contend for one dispatch switch (same rule as readers, see dispatch.go).
//
//	lrecon --op <name> [target]   one item, JSON on stdout
//	lrecon --list-ops             every registered item, one per line
type op struct {
	name  string
	route string // L: pure Go, G: ghidra headless, Y: external tool
	desc  string
	// needs says whether the item wants a target path. A tool-inventory item
	// (apktool version, java version) answers without a file.
	needs bool
	run   func(path string) (any, error)
}

var ops = map[string]op{}

func registerOp(o op) {
	if o.name == "" || o.run == nil {
		panic("registerOp: op without name or run")
	}
	if o.desc == "" {
		panic("registerOp: " + o.name + " has no description")
	}
	switch o.route {
	case "L", "G", "Y":
	default:
		panic("registerOp: " + o.name + " has route " + o.route)
	}
	if _, dup := ops[o.name]; dup {
		panic("registerOp: duplicate op: " + o.name)
	}
	ops[o.name] = o
}

// opNeedsExtra labels an item that takes no target path but still cannot run
// without a device, a session, or an argument. An item with needs=false and no
// entry here answers with no input at all: a tool inventory or a bookmark list.
var opNeedsExtra = map[string]string{
	// device
	"capture_adb_screen":         "device",
	"capture_native_ui_scenario": "device",
	"inspect_adb_device":         "device",
	"inspect_adb_display":        "device",
	"inspect_adb_window":         "device",
	"list_adb_packages":          "device",
	"list_adb_processes":         "device",
	"list_adb_services":          "device",
	"observe_native_ui":          "device",
	"read_adb_logcat":            "device",
	"trace_native_ui_action":     "device",
	// session
	"close_binary":           "session",
	"close_frida_session":    "session",
	"current_address":        "session",
	"current_document":       "session",
	"current_procedure":      "session",
	"frida_session_status":   "session",
	"get_navigation_context": "session",
	"instrument_with_frida":  "session",
	"list_documents":         "session",
	"load_frida_script":      "session",
	"next_address":           "session",
	"prev_address":           "session",
	"resume_frida_session":   "session",
	"start_frida_session":    "session",
	"trace_native_values":    "session",
	"unload_frida_session":   "session",
	"unload_frida_script":    "session",
	// arg
	"inspect_signal_decoders":  "arg",
	"scrub_output":             "arg",
	"unset_bookmark":           "arg",
	"update_analysis_settings": "arg",
}

// opNeeds is the published needs list: a target path when the op takes one,
// otherwise the extra input it cannot run without.
func opNeeds(o op) []string {
	if o.needs {
		return []string{"target"}
	}
	if label := opNeedsExtra[o.name]; label != "" {
		return []string{label}
	}
	return []string{}
}

// skip is the honest answer when an op's external tool is not installed: a
// refusal with a reason, not an empty result. Marshals to {"skipped": "..."}.
type skip struct {
	Reason string `json:"skipped"`
}

func skipf(format string, a ...any) *skip {
	return &skip{Reason: fmt.Sprintf(format, a...)}
}

// assumed records a target runOp inferred for an op called without one, so
// main can name it in the envelope instead of pretending the caller passed it.
var assumed struct {
	Path       string
	Confidence float64
}

// inferTarget answers the bare `lrecon --op NAME` case: an explicit LRECON_TARGET
// wins, then the only regular, non-hidden file in the working directory.
func inferTarget() (string, float64, bool) {
	if p := strings.TrimSpace(os.Getenv("LRECON_TARGET")); p != "" {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return p, 0.9, true
		}
	}
	ents, err := os.ReadDir(".")
	if err != nil {
		return "", 0, false
	}
	var only string
	for _, e := range ents {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if st, err := e.Info(); err != nil || !st.Mode().IsRegular() {
			continue
		}
		if only != "" {
			return "", 0, false
		}
		only = e.Name()
	}
	if only == "" {
		return "", 0, false
	}
	return "./" + only, 0.6, true
}

func runOp(name, path string) (any, error) {
	o, ok := ops[name]
	if !ok {
		return nil, fmt.Errorf("unknown op %q (%d registered; see --list-ops)", name, len(ops))
	}
	assumed.Path, assumed.Confidence = "", 0
	if o.needs && path == "" && !opTargetIsSelector(name) {
		path, assumed.Confidence, _ = inferTarget()
		assumed.Path = path
	}
	if o.needs && path == "" {
		return nil, fmt.Errorf("needs a target path: --target <path>")
	}
	return o.run(path)
}

// opNames is sorted so --list-ops and every proof built on it are stable.
func opNames() []string {
	names := make([]string, 0, len(ops))
	for name := range ops {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// opTargetIsSelector names the ops whose target is a value the device resolves
// (a URI, a package, a setting) rather than a document lrecon should open. Their
// target may look like a website or a process name without being one.
func opTargetIsSelector(name string) bool {
	switch name {
	case "resolve_adb_packages":
		return true
	}
	return false
}
