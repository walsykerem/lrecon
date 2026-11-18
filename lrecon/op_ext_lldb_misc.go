package main

// External-tool items for lldb: disassemble, breakpoint set/list/delete,
// watchpoint, image lookup, source list, frame variable, thread backtrace,
// diagnostics, thread/image/target list. Addendum 476-482, 490-495.

import (
	"os"
	"strings"
)

func init() {
	registerExtOp(extOp{
		name:  "lldb_disassemble",
		route: "Y",
		desc:  `lldb disassemble: lldb -o "disassemble -n NAME" -- FILE`,
		needs: true,
		run:   runLldbDisassemble,
	})
	registerExtOp(extOp{
		name:  "lldb_breakpoint_set",
		route: "Y",
		desc:  `lldb breakpoint set: lldb -o "breakpoint set -n NAME" -- FILE`,
		needs: true,
		run:   runLldbBreakpointSet,
	})
	registerExtOp(extOp{
		name:  "lldb_breakpoint_list",
		route: "Y",
		desc:  `lldb breakpoint list: lldb -o "breakpoint list" -- FILE`,
		needs: true,
		run:   runLldbBreakpointList,
	})
	registerExtOp(extOp{
		name:  "lldb_breakpoint_delete",
		route: "Y",
		desc:  `lldb breakpoint delete: lldb -o "breakpoint delete ID" -- FILE`,
		needs: true,
		run:   runLldbBreakpointDelete,
	})
	registerExtOp(extOp{
		name:  "lldb_watchpoint",
		route: "Y",
		desc:  `lldb watchpoint: lldb -o "watchpoint set expression EXPR" -- FILE`,
		needs: true,
		run:   runLldbWatchpoint,
	})
	registerExtOp(extOp{
		name:  "lldb_image_lookup",
		route: "Y",
		desc:  `lldb image lookup: lldb -o "image lookup -n NAME" -- FILE`,
		needs: true,
		run:   runLldbImageLookup,
	})
	registerExtOp(extOp{
		name:  "lldb_source_list",
		route: "Y",
		desc:  `lldb source list: lldb -o "source list -l LINE" -- FILE`,
		needs: true,
		run:   runLldbSourceList,
	})
	registerExtOp(extOp{
		name:  "lldb_frame_variable",
		route: "Y",
		desc:  `lldb frame variable: lldb -o "frame variable" -- FILE`,
		needs: true,
		run:   runLldbFrameVariable,
	})
	registerExtOp(extOp{
		name:  "lldb_thread_backtrace",
		route: "Y",
		desc:  `lldb thread backtrace: lldb -o "thread backtrace" -- FILE`,
		needs: true,
		run:   runLldbThreadBacktrace,
	})
	registerExtOp(extOp{
		name:  "lldb_diagnostics",
		route: "Y",
		desc:  `lldb diagnostics: lldb -o "diagnostics dump" -- FILE`,
		needs: true,
		run:   runLldbDiagnostics,
	})
	registerExtOp(extOp{
		name:  "lldb_thread_list_full",
		route: "Y",
		desc:  `lldb thread list full: lldb -o "thread list" -- FILE`,
		needs: true,
		run:   runLldbThreadListFull,
	})
	registerExtOp(extOp{
		name:  "lldb_image_list_full",
		route: "Y",
		desc:  `lldb image list full: lldb -o "image list" -- FILE`,
		needs: true,
		run:   runLldbImageListFull,
	})
	registerExtOp(extOp{
		name:  "lldb_target_list_full",
		route: "Y",
		desc:  `lldb target list full: lldb -o "target list" -- FILE`,
		needs: true,
		run:   runLldbTargetListFull,
	})
}

// lldbWithFile guards on file existence before paying for the dialog, like
// lldbPreflight, but names the file the caller gave.
func lldbWithFile(path string) error {
	if _, err := os.Stat(path); err != nil {
		return extRefuse(kindIO, "lldb target %s: %v", path, err)
	}
	if _, sk := rtTool("lldb", extLldbAlt); sk != nil {
		return extRefuse(kindNoEngine, "%s", sk.Reason)
	}
	return nil
}

func argOr(args []string, i int, def string) string {
	if len(args) > i && strings.TrimSpace(args[i]) != "" {
		return strings.TrimSpace(args[i])
	}
	return def
}

func runLldbDisassemble(path string, args []string) (any, error) {
	if err := lldbWithFile(path); err != nil {
		return nil, err
	}
	name := argOr(args, 0, "main")
	return lldbRun([]string{"disassemble -n " + name}, path, kindBadArg)
}

func runLldbBreakpointSet(path string, args []string) (any, error) {
	if err := lldbWithFile(path); err != nil {
		return nil, err
	}
	name := argOr(args, 0, "main")
	return lldbRun([]string{"breakpoint set -n " + name}, path, kindBadArg)
}

func runLldbBreakpointList(path string, args []string) (any, error) {
	if err := lldbWithFile(path); err != nil {
		return nil, err
	}
	return lldbRun([]string{"breakpoint list"}, path, kindBadArg)
}

func runLldbBreakpointDelete(path string, args []string) (any, error) {
	if err := lldbWithFile(path); err != nil {
		return nil, err
	}
	id := argOr(args, 0, "1")
	return lldbRun([]string{"breakpoint delete " + id}, path, kindBadArg)
}

func runLldbWatchpoint(path string, args []string) (any, error) {
	if err := lldbWithFile(path); err != nil {
		return nil, err
	}
	expr := argOr(args, 0, "0")
	return lldbRun([]string{"watchpoint set expression " + expr}, path, kindBadArg)
}

func runLldbImageLookup(path string, args []string) (any, error) {
	if err := lldbWithFile(path); err != nil {
		return nil, err
	}
	name := argOr(args, 0, "main")
	return lldbRun([]string{"image lookup -n " + name}, path, kindBadArg)
}

func runLldbSourceList(path string, args []string) (any, error) {
	if err := lldbWithFile(path); err != nil {
		return nil, err
	}
	line := argOr(args, 0, "1")
	return lldbRun([]string{"source list -l " + line}, path, kindBadArg)
}

func runLldbFrameVariable(path string, args []string) (any, error) {
	if err := lldbWithFile(path); err != nil {
		return nil, err
	}
	return lldbRun([]string{"frame variable"}, path, kindBadArg)
}

// lldbRunLive answers commands that need an inferior. Each lrecon item is one
// batch dialog and a fresh dialog has no process, so the target is launched at
// its entry point, asked, and killed inside the same dialog -- deterministic
// and nothing is left running.
func lldbRunLive(commands []string, target string, failKind errorKind) (any, error) {
	live := append([]string{"process launch --stop-at-entry"}, commands...)
	live = append(live, "process kill")
	res, err := lldbRun(live, target, failKind)
	if err != nil {
		if r, ok := err.(*extRefusal); ok && r.kind == kindNoEngine {
			if line := lldbLaunchFailureLine(r.msg); line != "" {
				return nil, extRefuse(kindBadArg, "lldb cannot launch %s: %s", target, line)
			}
		}
		return nil, err
	}
	if out, ok := res.(extOut); ok {
		if line := lldbLaunchFailureLine(out.Output); line != "" {
			return nil, extRefuse(kindBadArg, "lldb cannot launch %s: %s", target, line)
		}
	}
	return res, nil
}

// lldbLaunchFailureLine reports the refusal lldb prints when the file is not a
// runnable image; lldb still exits 0 there, so the transcript is the only clue.
func lldbLaunchFailureLine(s string) string {
	for _, l := range rtLines(s) {
		t := strings.TrimSpace(l)
		if strings.Contains(t, "process launch failed") || strings.Contains(t, "is not a valid executable") {
			return strings.TrimPrefix(t, "error: ")
		}
	}
	return ""
}

func runLldbThreadBacktrace(path string, args []string) (any, error) {
	if err := lldbWithFile(path); err != nil {
		return nil, err
	}
	return lldbRunLive([]string{"thread backtrace"}, path, kindBadArg)
}

func runLldbDiagnostics(path string, args []string) (any, error) {
	if err := lldbWithFile(path); err != nil {
		return nil, err
	}
	return lldbRun([]string{"diagnostics dump"}, path, kindBadArg)
}

func runLldbThreadListFull(path string, args []string) (any, error) {
	if err := lldbWithFile(path); err != nil {
		return nil, err
	}
	return lldbRunLive([]string{"thread list"}, path, kindBadArg)
}

func runLldbImageListFull(path string, args []string) (any, error) {
	if err := lldbWithFile(path); err != nil {
		return nil, err
	}
	return lldbRun([]string{"image list"}, path, kindBadArg)
}

func runLldbTargetListFull(path string, args []string) (any, error) {
	if err := lldbWithFile(path); err != nil {
		return nil, err
	}
	return lldbRun([]string{"target list"}, path, kindBadArg)
}
