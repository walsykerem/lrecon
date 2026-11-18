package main

// External-tool items for lldb register/memory/process work (addendum
// 483-489, route Y). Each item drives one `lldb --batch -o CMD -- FILE`
// dialog and answers with what lldb printed, or refuses honestly when lldb
// is absent (no_engine), the call is malformed (bad_arg, or needs_arg for a
// missing value), or the 60 s Y deadline hits (timeout: extRun maps a
// deadline kill to kindTimeout already).
//
// Batch lldb holds no live inferior, so a register/memory/thread command
// answers with lldb's one honest line — "Command requires a current process"
// — and exit 1. That is an answer, not a failure: the same rule the
// gdb_session_status lldb engine applies (lldbNoProcess). A write form only
// runs when the caller actually gave a value; without one the item does the
// read form (register) or refuses (memory write), so the contract pass with
// only a fixture file never mutates anything.

import (
	"os"
	"strconv"
	"strings"
)

func init() {
	registerExtOp(extOp{
		name:  "lldb_register_read",
		route: "Y",
		desc:  `lldb register read: lldb -o "register read" -- FILE`,
		needs: true,
		run:   runLldbRegisterRead,
	})
	registerExtOp(extOp{
		name:  "lldb_register_write",
		route: "Y",
		desc:  `lldb register write: lldb -o "register write REG VAL" -- FILE (without REG VAL it does a register read)`,
		needs: true,
		run:   runLldbRegisterWrite,
	})
	registerExtOp(extOp{
		name:  "lldb_memory_read",
		route: "Y",
		desc:  `lldb memory read: lldb -o "memory read ADDR" -- FILE (two args: -s SIZE ADDR)`,
		needs: true,
		run:   runLldbMemoryRead,
	})
	registerExtOp(extOp{
		name:  "lldb_memory_write",
		route: "Y",
		desc:  `lldb memory write: lldb -o "memory write ADDR BYTE" -- FILE (one arg ADDR=BYTE writes, a bare ADDR reads)`,
		needs: true,
		run:   runLldbMemoryWrite,
	})
	registerExtOp(extOp{
		name:  "lldb_expression",
		route: "Y",
		desc:  `lldb expression: lldb -o "expression EXPR" -- FILE`,
		needs: true,
		run:   runLldbExpression,
	})
	registerExtOp(extOp{
		name:  "lldb_process_launch",
		route: "Y",
		desc:  `lldb process launch: lldb -o "process launch" -- FILE (launches the target; a missing tool is no_engine)`,
		needs: true,
		run:   runLldbProcessLaunch,
	})
	registerExtOp(extOp{
		name:  "lldb_process_attach",
		route: "Y",
		desc:  `lldb process attach: lldb -o "process attach -p PID" -- FILE (target may be the PID itself)`,
		needs: true,
		run:   runLldbProcessAttach,
	})
}

// lldbPreflight refuses when the target cannot be read or lldb is missing,
// without paying for the dialog.
func lldbPreflight(path string) error {
	if _, err := os.Stat(path); err != nil {
		return extRefuse(kindIO, "lldb target %s: %v", path, err)
	}
	if _, sk := rtTool("lldb", extLldbAlt); sk != nil {
		return extRefuse(kindNoEngine, "%s", sk.Reason)
	}
	return nil
}

// lldbRun runs one batch dialog and shapes the answer. timeout and
// no_engine refusals from the plumbing pass through (a deadline kill is
// kindTimeout, a missing lldb kindNoEngine); lldb's own non-zero exit is
// either the no-process answer (ok, with the sentence kept) or a refusal
// with failKind (bad_arg for a malformed call, no_engine when attaching to
// a process lldb cannot reach).
func lldbRun(commands []string, target string, failKind errorKind) (any, error) {
	ctx, cancel := extCtx(extTimeoutY)
	defer cancel()
	out, errOut, err := extLldb(ctx, commands, target)
	noProc := lldbNoProcessLine(errOut)
	if err != nil && noProc == "" {
		if _, ok := err.(*extRefusal); ok {
			return nil, err
		}
		return nil, extRefuse(failKind, "lldb %s: %v", strings.Join(commands, " | "), err)
	}
	combined := strings.TrimSpace(out)
	if e := strings.TrimSpace(errOut); e != "" {
		if combined != "" {
			combined += "\n"
		}
		combined += e
	}
	if noProc != "" {
		note := "lldb needs a live process for this command; each lrecon item is one batch dialog, so no inferior exists (" + noProc + ")"
		if err != nil {
			// The command genuinely cannot run in a batch dialog, but the
			// reason is the missing inferior, not a missing lldb: keep the
			// no_engine class and say which one it is.
			return nil, extRefuse(kindNoEngine, "%s\nnote: %s", combined, note)
		}
		combined += "\nnote: " + note
	}
	toolArgs := append([]string{}, commands...)
	if target != "" {
		toolArgs = append(toolArgs, target)
	}
	return extOut{Tool: "lldb", Args: toolArgs, Output: combined, Lines: rtLines(combined)}, nil
}

func runLldbRegisterRead(path string, args []string) (any, error) {
	if err := lldbPreflight(path); err != nil {
		return nil, err
	}
	cmd := "register read"
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		cmd = "register read " + strings.TrimSpace(args[0])
	}
	return lldbRun([]string{cmd}, path, kindBadArg)
}

func runLldbRegisterWrite(path string, args []string) (any, error) {
	if err := lldbPreflight(path); err != nil {
		return nil, err
	}
	// A write needs a register and a value; without both the item only
	// reads, so a call that names no value can never mutate the target.
	switch {
	case len(args) >= 2:
		return lldbRun([]string{"register write " + strings.TrimSpace(args[0]) + " " + strings.TrimSpace(args[1])}, path, kindBadArg)
	case len(args) == 1 && strings.TrimSpace(args[0]) != "":
		return lldbRun([]string{"register read " + strings.TrimSpace(args[0])}, path, kindBadArg)
	}
	return lldbRun([]string{"register read"}, path, kindBadArg)
}

func runLldbMemoryRead(path string, args []string) (any, error) {
	if err := lldbPreflight(path); err != nil {
		return nil, err
	}
	switch {
	case len(args) >= 2:
		return lldbRun([]string{"memory read -s " + strings.TrimSpace(args[0]) + " " + strings.TrimSpace(args[1])}, path, kindBadArg)
	case len(args) == 1 && strings.TrimSpace(args[0]) != "":
		return lldbRun([]string{"memory read " + strings.TrimSpace(args[0])}, path, kindBadArg)
	}
	return nil, extRefuse(kindNeedsArg, "lldb_memory_read needs an address: usage: lrecon --ext-op lldb_memory_read FILE ADDR (two args: SIZE ADDR)")
}

func runLldbMemoryWrite(path string, args []string) (any, error) {
	if err := lldbPreflight(path); err != nil {
		return nil, err
	}
	switch {
	case len(args) >= 2:
		return lldbRun([]string{"memory write " + strings.TrimSpace(args[0]) + " " + strings.TrimSpace(args[1])}, path, kindBadArg)
	case len(args) == 1 && strings.TrimSpace(args[0]) != "":
		v := strings.TrimSpace(args[0])
		if addr, val, ok := strings.Cut(v, "="); ok && addr != "" && val != "" {
			return lldbRun([]string{"memory write " + addr + " " + val}, path, kindBadArg)
		}
		// A bare address reads: the safe side of a write item.
		return lldbRun([]string{"memory read " + v}, path, kindBadArg)
	}
	return nil, extRefuse(kindNeedsArg, "lldb_memory_write needs ADDR BYTE or ADDR=BYTE: usage: lrecon --ext-op lldb_memory_write FILE ADDR BYTE")
}

func runLldbExpression(path string, args []string) (any, error) {
	if err := lldbPreflight(path); err != nil {
		return nil, err
	}
	expr := strings.TrimSpace(strings.Join(args, " "))
	if expr == "" {
		return nil, extRefuse(kindNeedsArg, "lldb_expression needs an expression: usage: lrecon --ext-op lldb_expression FILE EXPR")
	}
	return lldbRun([]string{"expression " + expr}, path, kindBadArg)
}

func runLldbProcessLaunch(path string, args []string) (any, error) {
	if err := lldbPreflight(path); err != nil {
		return nil, err
	}
	// The item's whole job is launching the target; the fixture binary is
	// a tiny program that prints and exits, so the dialog ends on its own.
	return lldbRun([]string{"process launch"}, path, kindBadArg)
}

func runLldbProcessAttach(path string, args []string) (any, error) {
	if _, sk := rtTool("lldb", extLldbAlt); sk != nil {
		return nil, extRefuse(kindNoEngine, "%s", sk.Reason)
	}
	// The target may be the PID itself (`--ext-op lldb_process_attach PID`)
	// or the file with the PID as the first extra arg.
	pidStr := ""
	file := path
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		pidStr = strings.TrimSpace(args[0])
	} else if _, err := strconv.Atoi(strings.TrimSpace(path)); err == nil {
		pidStr = strings.TrimSpace(path)
		file = ""
	}
	if pidStr == "" {
		return nil, extRefuse(kindNeedsArg, "lldb_process_attach needs a pid: usage: lrecon --ext-op lldb_process_attach FILE PID (or PID as the target)")
	}
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid <= 0 {
		return nil, extRefuse(kindBadArg, "lldb_process_attach target %q is not a pid", pidStr)
	}
	if !pidAlive(pid) {
		return nil, extRefuse(kindNoEngine, "no live process with pid %d", pid)
	}
	if file != "" {
		if _, statErr := os.Stat(file); statErr != nil {
			// A non-file target is accepted as the file side of the
			// dialog only if it exists; the pid side is already settled.
			return nil, extRefuse(kindIO, "lldb target %s: %v", file, statErr)
		}
	}
	return lldbRun([]string{"process attach -p " + strconv.Itoa(pid)}, file, kindNoEngine)
}
