package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// RT items spawn external tools against live devices and processes. They never
// feed the digest (live targets stay a non-goal, see main.go): each one is an
// explicit, caller-invoked extra, and each refuses with a skip when its tool or
// its device is absent instead of inventing a result.

// rtTimeout bounds one spawned tool: a hung device or a waiting debugger must
// not hang the op. Rows that need longer say so at their own call site.
const rtTimeout = 60 * time.Second

// rtAlternatives are the alternatives a skip has to name, so a reader knows
// what to install or what to reach for instead.
const (
	rtAdbAlt   = "an alternative is gadb (electricbubble/gadb, MIT, pure Go) over 127.0.0.1:5037"
	rtFridaAlt = "an alternative is frida-go (ISC, //go:build frida, cgo) holding the session in-process"

	rtRizinAlt  = "an alternative is rizin 0.7+ (LGPL-3.0, spawn only; rz-pipe has no LICENSE so it is not vendored)"
	rtSampleAlt = "no alternative on linux (perf script reads perf.data; /proc/<pid>/task/*/stack needs CAP_SYS_ADMIN)"
)

func rtCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), rtTimeout)
}

// rtTool finds an external tool. Absent is a skip naming the tool and the §y
// alternative: an opaque "executable file not found" tells the reader nothing.
func rtTool(tool, alt string) (string, *skip) {
	bin, err := exec.LookPath(tool)
	if err != nil {
		if !errors.Is(err, exec.ErrNotFound) && !errors.Is(err, fs.ErrNotExist) {
			// Under load fork/exec fails with EAGAIN and LookPath reports it as
			// if the tool were missing; "not installed" would be a lie.
			return "", skipf("%s could not be started: %v (the host is out of processes or file descriptors)", tool, err)
		}
		return "", skipf("%s not installed: %s", tool, alt)
	}
	return bin, nil
}

// rtRun runs one command and returns stdout as text.
func rtRun(ctx context.Context, bin string, args ...string) (string, error) {
	out, errOut, err := rtRunTextStreams(ctx, bin, args...)
	if err != nil {
		return out, rtRunError(ctx, bin, args, out, errOut, err)
	}
	return out, nil
}

// rtRunRaw is rtRun for binary output (a screencap PNG, a pulled file).
// A tool that exists but fails is an error carrying stderr's first line; the
// exit status alone does not say why.
func rtRunRaw(ctx context.Context, bin string, args ...string) ([]byte, error) {
	out, errOut, err := rtRunRawStreams(ctx, bin, args...)
	if err != nil {
		return out, rtRunError(ctx, bin, args, string(out), string(errOut), err)
	}
	return out, nil
}

// rtRunError explains a failed tool: a deadline kill reads as internal without
// the context, and frida prints its failure on stdout, so both streams are read.
func rtRunError(ctx context.Context, bin string, args []string, out, errOut string, err error) error {
	// exec.CommandContext kills the child at the deadline, and the bare
	// "signal: killed" reads as internal; name the deadline instead so the
	// envelope can answer kind=timeout.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("%s %s: %s", filepath.Base(bin), strings.Join(args, " "), ctxErr)
	}
	if line := rtFirstLine(errOut); line != "" {
		return fmt.Errorf("%s %s: %s", filepath.Base(bin), strings.Join(args, " "), line)
	}
	// frida prints "Failed to attach: …" on stdout and exits 1.
	if line := rtFirstLine(out); line != "" {
		return fmt.Errorf("%s %s: %s", filepath.Base(bin), strings.Join(args, " "), line)
	}
	return fmt.Errorf("%s %s: %w", filepath.Base(bin), strings.Join(args, " "), err)
}

// rtRunRawStreams is rtRunRaw with the failure stream kept: a caller that has
// to explain a non-zero exit can quote the line that says why, because the
// first stderr line is often only the command echo ("adb: failed to install
// x.apk:") with the reason on the next one. Both streams are whole because a
// pulled or captured file is an answer, not a log.
func rtRunRawStreams(ctx context.Context, bin string, args ...string) (stdout, stderr []byte, err error) {
	var out, errOut bytes.Buffer
	err = rtSpawn(ctx, bin, args, &out, &errOut)
	return out.Bytes(), errOut.Bytes(), err
}

// rtRunTextStreams is rtRunRawStreams for a tool whose output is a log: the
// last maxExtOutput bytes are kept instead of the whole stream, so a logcat or
// a chatty JVM costs a fixed buffer rather than the machine's memory.
func rtRunTextStreams(ctx context.Context, bin string, args ...string) (stdout, stderr string, err error) {
	var out, errOut tailBuffer
	err = rtSpawn(ctx, bin, args, &out, &errOut)
	return string(out.buf), string(errOut.buf), err
}

// maxExtOutput bounds one external tool's captured log. Only a line or two is
// read from it, and adb logcat, jadx, ghidra and frida write without a bound.
const maxExtOutput = 1 << 20

// tailBuffer keeps the last maxExtOutput bytes written to it. The tail is the
// useful half: tools put the reason they failed at the end.
type tailBuffer struct {
	buf []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if n >= maxExtOutput {
		t.buf = append(t.buf[:0], p[n-maxExtOutput:]...)
		return n, nil
	}
	t.buf = append(t.buf, p...)
	if over := len(t.buf) - maxExtOutput; over > 0 {
		t.buf = append(t.buf[:0], t.buf[over:]...)
	}
	return n, nil
}

func (t *tailBuffer) String() string { return string(t.buf) }

// rtSpawn is the one place an RT tool is started: its own process group so the
// deadline kills the helpers it spawned, and WaitDelay so a helper that still
// holds the pipes cannot keep the call blocked past the deadline.
func rtSpawn(ctx context.Context, bin string, args []string, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	setpgroup(cmd)
	cmd.Cancel = func() error { return killGroup(cmd.Process.Pid) }
	cmd.WaitDelay = 2 * time.Second
	cmd.Stdout, cmd.Stderr = stdout, stderr
	return cmd.Run()
}

func rtFirstLine(s string) string {
	for l := range strings.SplitSeq(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return ""
}

// rt2FirstLine is the name the adb ops still use for rtFirstLine; one helper,
// two names until those call sites move.
func rt2FirstLine(s string) string { return rtFirstLine(s) }

// rtCauseLine keeps the one line a reviewer can paste into a search: the first
// error-looking line, else the first informative line, never a wall of Ghidra
// log with its JVM banner and INFO chatter.
func rtCauseLine(parts ...any) string {
	var fallback string
	for _, p := range parts {
		var s string
		switch v := p.(type) {
		case string:
			s = v
		case error:
			if v != nil {
				s = v.Error()
			}
		}
		for line := range strings.SplitSeq(s, "\n") {
			line = strings.TrimSpace(line)
			switch {
			case line == "",
				strings.HasPrefix(line, "openjdk version"),
				strings.HasPrefix(line, "OpenJDK "),
				strings.HasPrefix(line, "Picked up "),
				strings.HasPrefix(line, "WARNING:"),
				strings.HasPrefix(line, "INFO "),
				strings.HasPrefix(line, "WARN "):
				continue
			}
			low := strings.ToLower(line)
			if strings.Contains(low, "error") || strings.Contains(low, "exception") ||
				strings.Contains(low, "cannot ") || strings.Contains(low, "unable ") {
				return line
			}
			if fallback == "" {
				fallback = line
			}
		}
	}
	if fallback != "" {
		return fallback
	}
	return "no output"
}

// rtLines splits text into non-empty trimmed lines.
func rtLines(s string) []string {
	var out []string
	for l := range strings.SplitSeq(s, "\n") {
		if l = strings.TrimRight(l, "\r"); strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// rtDevice is one `adb devices -l` row.
type rtDevice struct {
	Serial      string `json:"serial"`
	State       string `json:"state"`
	Product     string `json:"product,omitempty"`
	Model       string `json:"model,omitempty"`
	TransportID string `json:"transport_id,omitempty"`
}

// rtParseDevices reads `adb devices -l` / `host:devices-l` output: the header
// line, then `<serial> <state> [key:value ...]`.
func rtParseDevices(out string) []rtDevice {
	// An empty table is an answer ("nothing attached"), not a missing one:
	// JSON must carry [] so the caller can tell "no devices" from "no field".
	devs := []rtDevice{}
	for _, l := range rtLines(out) {
		if strings.HasPrefix(l, "List of devices attached") || strings.HasPrefix(l, "*") {
			continue
		}
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		d := rtDevice{Serial: f[0], State: f[1]}
		for _, kv := range f[2:] {
			k, v, ok := strings.Cut(kv, ":")
			if !ok {
				continue
			}
			switch k {
			case "product":
				d.Product = v
			case "model":
				d.Model = v
			case "transport_id":
				d.TransportID = v
			}
		}
		devs = append(devs, d)
	}
	return devs
}

func rtAdb() (string, *skip) { return rtTool("adb", rtAdbAlt) }

// rtAdbSerial refuses unless exactly one device is in state "device": a live
// answer about a device that is not attached cannot be observed.
func rtAdbSerial(ctx context.Context, adb string, cmd ...string) (string, *skip, error) {
	out, err := rtRun(ctx, adb, "devices", "-l")
	if err != nil {
		return "", nil, err
	}
	devs := rtParseDevices(out)
	var ready []string
	for _, d := range devs {
		if d.State == "device" {
			ready = append(ready, d.Serial)
		}
	}
	switch len(ready) {
	case 0:
		// Name the call that needs a device: "no device" alone does not say
		// which op asked, and the sweep wants one refusal per call site.
		what := ""
		if len(cmd) > 0 && cmd[0] != "" {
			what = " (`adb shell " + strings.Join(cmd, " ") + "` needs it)"
		}
		if len(devs) > 0 {
			return "", skipf("no device ready: %d attached, none in state \"device\"%s: %s", len(devs), what, rtAdbAlt), nil
		}
		return "", skipf("no device attached%s: connect one and retry; %s", what, rtAdbAlt), nil
	case 1:
		return ready[0], nil, nil
	}
	// adb honours ANDROID_SERIAL itself, so a deliberate choice is not a guess:
	// refusing here would make the documented multi-device escape hatch unusable.
	if want := strings.TrimSpace(os.Getenv("ANDROID_SERIAL")); want != "" {
		if slices.Contains(ready, want) {
			return want, nil, nil
		}
		return "", nil, fmt.Errorf("ANDROID_SERIAL=%s is not attached; ready devices: %s", want, strings.Join(ready, ", "))
	}
	return "", nil, fmt.Errorf("%d devices ready (%s): set ANDROID_SERIAL=<serial> to pick one, or disconnect all but one", len(ready), strings.Join(ready, ", "))
}

// rtAdbShell runs one command inside the device shell.
func rtAdbShell(ctx context.Context, adb, serial string, args ...string) (string, error) {
	return rtRun(ctx, adb, append([]string{"-s", serial, "shell"}, args...)...)
}

// rtPNGInfo reads width/height from a PNG's IHDR. The signature and the chunk
// name are checked first: `screencap -p` without -p on old APIs returns raw
// pixels, and treating those as a PNG would be a fabricated image.
func rtPNGInfo(b []byte) (int, int, error) {
	if len(b) < 24 {
		return 0, 0, fmt.Errorf("screencap returned %d bytes, need 24 for an IHDR", len(b))
	}
	if !bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")) || string(b[12:16]) != "IHDR" {
		return 0, 0, fmt.Errorf("screencap output is not a PNG (no signature/IHDR): API<24 needs screencap -p to a file, then pull")
	}
	w := int(binary.BigEndian.Uint32(b[16:20]))
	h := int(binary.BigEndian.Uint32(b[20:24]))
	if w <= 0 || h <= 0 {
		return 0, 0, fmt.Errorf("PNG IHDR has %dx%d pixels", w, h)
	}
	return w, h, nil
}

// rtScreenshot is the observed PNG: size from the IHDR, never from a guess.
type rtScreenshot struct {
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
	File   string `json:"file,omitempty"`
}

// rtScreencap is §y y10's transport: `exec-out` is binary safe, so no pty and
// no LF→CRLF damage, and no base64 trick is needed. The raw PNG is returned
// too, for the caller that has somewhere to write it.
func rtScreencap(ctx context.Context, adb, serial string) (rtScreenshot, []byte, error) {
	raw, err := rtRunRaw(ctx, adb, "-s", serial, "exec-out", "screencap", "-p")
	if err != nil {
		return rtScreenshot{}, nil, err
	}
	w, h, err := rtPNGInfo(raw)
	if err != nil {
		return rtScreenshot{}, nil, err
	}
	sum := sha256.Sum256(raw)
	return rtScreenshot{Width: w, Height: h, Bytes: len(raw), SHA256: hex.EncodeToString(sum[:])}, raw, nil
}
