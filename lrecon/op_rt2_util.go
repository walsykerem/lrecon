package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"
)

// RT2 ops are one-shot adapters around the external tools final.md §y names:
// adb (y33-y56), rizin (y46/y47/y52) and gdb (y51). Nothing here is linked into
// the build, and nothing runs from --json.
const (
	rt2Timeout        = 20 * time.Second
	rt2SessionTimeout = 10 * time.Second

	// rt2FridaSeconds is the value frida's own `-t` gets: the CLI ends the
	// one-shot spawn session itself, one second before this side would have to
	// kill it. frida 17 removed `--no-pause`; a spawn resumes by default.
	rt2FridaSeconds = 9

	// rt2TransferTimeout bounds one adb pull/push: a 40MB APK over a loaded
	// emulator takes minutes, and the 20s probe budget would refuse it.
	rt2TransferTimeout = 180 * time.Second

	// rt2FridaProbeTimeout bounds one `frida-ps -j` probe: a device that
	// frida-ls-devices lists but whose frida-server is gone must not stall the
	// op for the full rt2Timeout.
	rt2FridaProbeTimeout = 12 * time.Second

	rt2AdbAlt   = "install Android platform-tools and attach a device; the commands are `adb shell …` (final.md y10-y57)"
	rt2FridaAlt = "install frida-tools (`python3 -m pip install --user frida-tools`; on macOS its scripts land in ~/Library/Python/<v>/bin, on Linux in ~/.local/bin, so add that directory to PATH) — frida also serves the local machine without a USB device, and an alternative is frida-go (ISC, //go:build frida, cgo) holding the session in-process (final.md y34-y57)"
	rt2GdbAlt   = "install gdb (absent on Apple Silicon) or use `lldb --no-lldbinit -o 'process launch -s' -o bt -- <bin>` (final.md y51)"
)

// rt2Exec is the one place an external tool is spawned. A missing tool is a
// skip naming its alternative; a failing tool is an error carrying stderr's
// first line; a deadline kill is reported so a session op can tell "still
// running, as expected" from "crashed".
func rt2Exec(tool, alt, stdin string, d time.Duration, args ...string) (stdout string, expired bool, sk *skip, err error) {
	path, lookErr := exec.LookPath(tool)
	if lookErr != nil {
		if !errors.Is(lookErr, exec.ErrNotFound) && !errors.Is(lookErr, fs.ErrNotExist) {
			// Under a loaded host fork/exec fails with EAGAIN and LookPath
			// reports it as if the tool were missing. Saying "not installed"
			// there hides a machine problem behind a wrong answer.
			return "", false, nil, fmt.Errorf("%s could not be started: %v (the host is out of processes or file descriptors, not missing the tool)", tool, lookErr)
		}
		return "", false, skipf("%s not installed: %s", tool, alt), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	// These tools are usually shell wrappers around a JVM (apktool, jadx):
	// killing only the wrapper leaves java holding our pipes and still writing
	// into the temp tree the caller removes next. Own the group, kill the group.
	setpgroup(cmd)
	pgid := 0
	cmd.Cancel = func() error {
		pgid = cmd.Process.Pid
		return killGroup(pgid)
	}
	// A wrapper that exits on time but leaves the JVM holding our pipes must
	// not stall the call; the group kill below ends it.
	cmd.WaitDelay = 5 * time.Second
	var out, errb tailBuffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	runErr := cmd.Run()
	if pgid == 0 && cmd.Process != nil {
		pgid = cmd.Process.Pid
	}
	// A wrapper that exits first leaves its JVM alive under the same group; a
	// stray child must not outlive the call it was started for.
	if pgid > 0 {
		killGroup(pgid)
	}
	if errors.Is(runErr, exec.ErrWaitDelay) {
		// The wrapper exited 0 and only a child we just killed held the pipes.
		runErr = nil
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return out.String(), true, nil, nil
	}
	if runErr != nil {
		msg := rtFirstLine(errb.String())
		if msg == "" {
			// frida prints its failures ("Failed to attach: …", "Failed to
			// spawn: …") on stdout and exits 1, so stderr alone loses the why.
			msg = rtFirstLine(out.String())
		}
		// `am start -W` opens with "Starting: Intent {…}" and only then says
		// "Error: Activity class … does not exist": the first line is the
		// banner, not the reason.
		if cause := rt2Cause(out.String() + "\n" + errb.String()); cause != "" {
			msg = cause
		}
		if msg == "" {
			msg = runErr.Error()
		}
		return out.String(), false, nil, fmt.Errorf("%s %s failed: %s", tool, strings.Join(args, " "), rt2StableMsg(msg))
	}
	return out.String(), false, nil, nil
}

// rt2Cause is the line that names the failure when the tool prints a banner
// first and its reason later (am, dpm, cmd).
func rt2Cause(text string) string {
	for line := range strings.SplitSeq(text, "\n") {
		l := strings.TrimSpace(line)
		for _, p := range []string{"Error:", "FAIL:", "adb: error:", "Failure [", "Exception:"} {
			if strings.HasPrefix(l, p) {
				return l
			}
		}
	}
	return ""
}

// rt2Run is the one-shot form: a timeout is a failure, not empty output.
func rt2Run(tool, alt string, args ...string) (string, *skip, error) {
	out, expired, sk, err := rt2Exec(tool, alt, "", rt2Timeout, args...)
	if sk != nil || err != nil {
		return out, sk, err
	}
	if expired {
		return "", nil, fmt.Errorf("%s %s timed out after %s", tool, strings.Join(args, " "), rt2Timeout)
	}
	return out, nil, nil
}

// rt2RunTimeout is rt2Run with its own deadline: transfers and dumps have a
// size or a device load that the 20s probe budget cannot cover.
func rt2RunTimeout(tool, alt string, d time.Duration, args ...string) (string, *skip, error) {
	out, expired, sk, err := rt2Exec(tool, alt, "", d, args...)
	if sk != nil || err != nil {
		return out, sk, err
	}
	if expired {
		return "", nil, fmt.Errorf("%s %s timed out after %s", tool, strings.Join(args, " "), d)
	}
	return out, nil, nil
}

// rt2AdbTransfer is one pull or push.
func rt2AdbTransfer(args ...string) (string, *skip, error) {
	return rt2RunTimeout("adb", rt2AdbAlt, rt2TransferTimeout, args...)
}

// rt2APKTimeout bounds one apk decode. apktool and jadx are JVMs: a 20-40 MB
// APK is minutes of decode work, not the 20s probe, so this defaults to the
// transfer budget and LRECON_APK_TIMEOUT (any time.ParseDuration value) can
// name another.
func rt2APKTimeout() time.Duration {
	if v := strings.TrimSpace(os.Getenv("LRECON_APK_TIMEOUT")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return rt2TransferTimeout
}

// rt2RunSession runs a tool that stays attached (frida). The deadline kill is
// the normal end of such a session, so `expired` is returned instead of an error.
func rt2RunSession(tool, alt string, args ...string) (string, bool, *skip, error) {
	return rt2Exec(tool, alt, "", rt2SessionTimeout, args...)
}

func rt2Installed(tool string) bool {
	_, err := exec.LookPath(tool)
	return err == nil
}

// rt2Throughput is the copy rate adb prints with a successful transfer:
// "1 file pushed, 0 skipped. 9.3 MB/s (8192 bytes in 0.001s)". The rate is a
// clock reading, so two identical calls reported two different strings.
var rt2Throughput = regexp.MustCompile(`\s*\d+(?:\.\d+)? ?[KMG]B/s \([^)]*\)`)

// rt2AdbStamp is adb's log prefix: "11-02 03:44:25.944 98321 4724641 F adb :".
// The clock and the pids are the run, not the failure.
var rt2AdbStamp = regexp.MustCompile(`\d\d-\d\d \d\d:\d\d:\d\d\.\d+ +\d+ +\d+ [A-Z] [A-Za-z_.]+ *: `)

// rt2StableMsg keeps the outcome and drops the measurement, so a failure text
// is a function of the input rather than of how fast the machine ran.
func rt2StableMsg(msg string) string {
	msg = rt2AdbStamp.ReplaceAllString(msg, "")
	return strings.TrimSpace(strings.ReplaceAll(rt2Throughput.ReplaceAllString(msg, ""), " .", "."))
}

func rt2Lines(s string) []string {
	var lines []string
	for line := range strings.SplitSeq(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// rt2Pair splits the single target an op receives into the two arguments the
// documented command needs. The format is stated in each op's description.
func rt2Pair(target, sep string) (string, string, error) {
	a, b, ok := strings.Cut(target, sep)
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if !ok || a == "" || b == "" {
		return "", "", fmt.Errorf("target %q is not <first>%s<second>", target, sep)
	}
	return a, b, nil
}

func rt2SHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// rt2AdbReady is the device gate every adb op runs first. cmd is the
// device-side command the op was about to run; naming it makes the refusal say
// what needs a device instead of only that one is missing.
func rt2AdbReady(cmd ...string) (*skip, error) {
	out, sk, err := rt2Run("adb", rt2AdbAlt, "devices")
	if sk != nil || err != nil {
		return sk, err
	}
	var ready []string
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == "device" {
			ready = append(ready, f[0])
		}
	}
	if len(ready) == 0 {
		if len(cmd) > 0 && cmd[0] != "" {
			return skipf("no device attached: `adb shell %s` needs one; `adb devices -l` lists none in state \"device\"; %s",
				strings.Join(cmd, " "), rt2AdbAlt), nil
		}
		return skipf("no device attached: %s", rt2AdbAlt), nil
	}
	// adb reads ANDROID_SERIAL itself; the gate only has to stop a real
	// ambiguity, and it must not reject a serial the user deliberately picked.
	if want := strings.TrimSpace(os.Getenv("ANDROID_SERIAL")); want != "" {
		if slices.Contains(ready, want) {
			return nil, nil
		}
		return nil, fmt.Errorf("ANDROID_SERIAL=%s is not attached; ready devices: %s", want, strings.Join(ready, ", "))
	}
	if len(ready) > 1 {
		return nil, fmt.Errorf("%d devices ready (%s): set ANDROID_SERIAL=<serial> to pick one, or disconnect all but one", len(ready), strings.Join(ready, ", "))
	}
	return nil, nil
}

func rt2AdbRun(args ...string) (string, *skip, error) {
	return rt2Run("adb", rt2AdbAlt, args...)
}

func rt2AdbShell(args ...string) (string, *skip, error) {
	return rt2AdbRun(append([]string{"shell"}, args...)...)
}

type rt2FridaDevice struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
	OS   string `json:"os,omitempty"`
}

var rt2FridaOSNames = map[string]bool{
	"darwin": true, "macos": true, "linux": true, "windows": true,
	"android": true, "ios": true, "freebsd": true, "qnx": true, "generic": true,
}

type rt2FridaProcess struct {
	PID        int    `json:"pid"`
	Name       string `json:"name"`
	Identifier string `json:"identifier,omitempty"`
}

// rt2AMStatus reads the `Status:` line `am start -W` prints; its absence means
// the command failed, so it is an error rather than an empty status.
func rt2AMStatus(out string) (string, error) {
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "Status:"); ok {
			return strings.TrimSpace(v), nil
		}
	}
	return "", fmt.Errorf("am start printed no Status: line (first line: %q)", rtFirstLine(out))
}
