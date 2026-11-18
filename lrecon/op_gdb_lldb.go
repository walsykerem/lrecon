package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// gdb does not exist on macOS by default; lldb does, and it is the same kind of
// batch debugger. The file-level gdb ops (console, thread list, close) do not
// need a live inferior, so they get an lldb engine instead of a dead end.
//
// A live session is still out of scope (B7): start_gdb_session keeps refusing
// before it looks for a tool, exactly as rapor-canli-hedef.md documents.
const lldbAlt = "lldb --batch (llvm, Apache-2.0 WITH LLVM-exception) ships with the macOS toolchain"

// lldbTool finds lldb, or returns a skip that still names gdb and an
// alternative: a reader who installed neither has to learn both names.
func lldbTool() (string, *skip) {
	bin, err := exec.LookPath("lldb")
	if err != nil {
		// Under load fork/exec fails with EAGAIN and LookPath reports it as if
		// the tool were missing; "not installed" would be a lie (same rule as
		// rtTool).
		if !errors.Is(err, exec.ErrNotFound) && !errors.Is(err, fs.ErrNotExist) {
			return "", skipf("lldb could not be started: %v (the host is out of processes or file descriptors)", err)
		}
		return "", skipf("lldb not installed (gdb_console, gdb_session_status and close_gdb_session run on it): %s; an alternative is gdb >= 11 by hand, `gdb --batch -nx -ex \"info threads\" -- binary`", lldbAlt)
	}
	return bin, nil
}

// lldbDialog runs one batch dialog. lldb prints command errors on stderr and
// often still exits 0, so stdout and stderr are kept apart and the caller
// decides what the transcript means.
func lldbDialog(ctx context.Context, lldb, file string, cmds ...string) (string, string, error) {
	args := []string{"--batch", "--no-lldbinit"}
	for _, c := range cmds {
		args = append(args, "-o", c)
	}
	if file != "" {
		args = append(args, "--", file)
	}
	cmd := exec.CommandContext(ctx, lldb, args...)
	// The deadline has to end the whole tree lldb spawned, not only the process
	// Go started: the child gets its own process group and Cancel kills that
	// group. Measured before the fix: a fake lldb's background helper was still
	// alive 6 s after lrecon returned at its 60 s deadline.
	setpgroup(cmd)
	cmd.Cancel = func() error { return killGroup(cmd.Process.Pid) }
	// lldb can leave a helper holding the pipes after the batch exits. Without
	// a wait delay, Wait blocks until that helper closes them, so a hung dialog
	// outlives its deadline instead of being killed with the child.
	cmd.WaitDelay = 2 * time.Second
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return out.String(), errOut.String(), fmt.Errorf("lldb %s: %s", filepath.Base(file), ctxErr)
	}
	if err != nil {
		if line := rtFirstLine(errOut.String()); line != "" {
			return out.String(), errOut.String(), fmt.Errorf("lldb: %s", line)
		}
		return out.String(), errOut.String(), fmt.Errorf("lldb: %w", err)
	}
	return out.String(), errOut.String(), nil
}

// lldbNoProcessLine reports the one refusal that is an answer, not a failure:
// lldb exits non-zero when a command needs a live process, and lrecon
// deliberately runs one batch dialog per op. The transcript carries the exact
// sentence.
//
// The whole diagnostic body is compared, not a substring: lldb echoes the
// target path inside the same "error:" line, so a file literally named
// "no current process" would otherwise turn a real failure into a success
// (measured: it did, and gdb_console refused the same file with bad_arg).
func lldbNoProcessLine(errOut string) string {
	for _, l := range lldbErrors(errOut) {
		body := strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(l, "error:")), ".")
		if body == "Command requires a current process" || body == "no current process" {
			return l
		}
	}
	return ""
}

func lldbNoProcess(errOut string) bool { return lldbNoProcessLine(errOut) != "" }

// lldbErrors keeps only the lines lldb prefixed with "error:": a target path
// echoed back by `target create` can contain the same words as a diagnostic,
// and a missing "/tmp/no process" must stay an io error, not a no-inferior
// answer.
func lldbErrors(s string) []string {
	var out []string
	for _, l := range rtLines(s) {
		if t := strings.TrimSpace(l); strings.HasPrefix(t, "error:") {
			out = append(out, t)
		}
	}
	return out
}

// lldbTranscript joins both streams in the order a reader needs: what lldb
// printed, then whatever it complained about.
func lldbTranscript(out, errOut string) []string {
	lines := rtLines(out)
	for _, l := range rtLines(errOut) {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

// gdbConsoleLLDB is the lldb engine for gdb_console: `target list` names the
// file lldb loaded and `image list` resolves every dylib it links. That is the
// same file-level console pass gdb gives with no inferior started.
func gdbConsoleLLDB(bin string) (any, error) {
	lldb, sk := lldbTool()
	if sk != nil {
		return sk, nil
	}
	ctx, cancel := rtCtx()
	defer cancel()
	out, errOut, err := lldbDialog(ctx, lldb, bin, "target list", "image list")
	if err != nil {
		return nil, err
	}
	res := rtGdbConsole{Binary: bin, Engine: "lldb", Output: lldbTranscript(out, errOut)}
	if len(res.Output) == 0 {
		return nil, fmt.Errorf("lldb printed nothing for %s", bin)
	}
	return res, nil
}

// gdbSessionStatusLLDB is the lldb engine for gdb_session_status. lldb only
// lists threads for a live process, so with the batch dialog lrecon runs the
// honest answer is an empty list plus the reason lldb gave.
func gdbSessionStatusLLDB(bin string) (any, error) {
	lldb, sk := lldbTool()
	if sk != nil {
		return sk, nil
	}
	ctx, cancel := rtCtx()
	defer cancel()
	out, errOut, err := lldbDialog(ctx, lldb, bin, "thread list")
	if err != nil && !lldbNoProcess(errOut) {
		return nil, err
	}
	res := rtGdbStatus{Binary: bin, Engine: "lldb", Threads: []rtGdbThread{}, Output: lldbTranscript(out, errOut)}
	if l := lldbNoProcessLine(errOut); l != "" {
		res.Stopped = "no-inferior"
		res.Note = "lldb needs a live process for a thread list; each lrecon op is one batch dialog, so no inferior exists (" + strings.TrimSpace(l) + ")"
		return res, nil
	}
	for _, l := range rtLines(out) {
		if m := rtLLDBThread.FindStringSubmatch(l); m != nil {
			res.Threads = append(res.Threads, rtGdbThread{ID: m[1]})
		}
		if m := rtLLDBStop.FindStringSubmatch(l); m != nil && res.Stopped == "" {
			res.Stopped = m[1]
		}
	}
	if len(res.Threads) == 0 && res.Stopped == "" {
		res.Stopped = "no-inferior"
		res.Note = "lldb printed no thread list and no stop reason for " + filepath.Base(bin)
	}
	return res, nil
}

// closeGdbSessionLLDB answers the close for the lldb engine. lrecon never keeps
// a debugger process alive between invocations, so there is nothing left to
// close and say-so is the truthful answer; a fake `exited: true` would claim a
// session that never existed.
func closeGdbSessionLLDB(bin string) (any, error) {
	lldb, sk := lldbTool()
	if sk != nil {
		return sk, nil
	}
	ctx, cancel := rtCtx()
	defer cancel()
	out, errOut, err := lldbDialog(ctx, lldb, bin, "process status")
	if err != nil && !lldbNoProcess(errOut) {
		return nil, err
	}
	res := rtGdbClosed{
		Binary: bin,
		Engine: "lldb",
		Exited: false,
		Output: lldbTranscript(out, errOut),
		Note:   "no lldb session is held between invocations: each op is one batch dialog, so there is nothing left to close",
	}
	return res, nil
}
