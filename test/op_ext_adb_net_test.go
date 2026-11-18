package main

// LANE06: adb net/state validation happens before any tool is touched, so a
// missing adb must not turn a bad argument into a misleading "no_engine".
// Fake adb shims prove the happy path reaches the tool with exact args.

import (
	"errors"
	"strings"
	"testing"
)

func lane06AdbRefuse(t *testing.T, err error, wantKind errorKind, wantMsg string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want refusal %s, got nil", wantKind)
	}
	var ref *extRefusal
	if !errors.As(err, &ref) {
		t.Fatalf("want *extRefusal, got %T: %v", err, err)
	}
	if ref.kind != wantKind {
		t.Fatalf("kind = %q, want %q (%v)", ref.kind, wantKind, ref.msg)
	}
	if !strings.Contains(ref.msg, wantMsg) {
		t.Fatalf("msg %q does not contain %q", ref.msg, wantMsg)
	}
}

func TestAdbNetArgValidationBeforeTool(t *testing.T) {
	rtNoTools(t)
	_, err := adbForwardAdd("", nil)
	lane06AdbRefuse(t, err, kindNeedsArg, "tcp:LOCAL")
	_, err = adbForwardAdd("tcp:8080", []string{" "})
	lane06AdbRefuse(t, err, kindNeedsArg, "REMOTE")
	_, err = adbReverseAdd("", nil)
	lane06AdbRefuse(t, err, kindNeedsArg, "tcp:REMOTE")
	_, err = adbConnect("", nil)
	lane06AdbRefuse(t, err, kindNeedsArg, "HOST")
	_, err = adbKeygen("", nil)
	lane06AdbRefuse(t, err, kindNeedsArg, "FILE")
	_, err = adbServer("", []string{"frobnicate"})
	lane06AdbRefuse(t, err, kindBadArg, "not one of")
	if _, err := runExtOp("adb_connect", "", nil); err == nil || !strings.Contains(err.Error(), "needs a target path") {
		t.Fatalf("runExtOp no-target = %v", err)
	}
}

func TestAdbStateArgValidationBeforeTool(t *testing.T) {
	rtNoTools(t)
	_, err := runAdbTcpip("dev", nil)
	lane06AdbRefuse(t, err, kindNeedsArg, "needs a port")
	for _, bad := range []string{"abc", "0", "65536", "-1", "12x"} {
		t.Run("port "+bad, func(t *testing.T) {
			_, err := runAdbTcpip("dev", []string{bad})
			lane06AdbRefuse(t, err, kindBadArg, "not a port number")
		})
	}
	_, err = runAdbEmu("dev", []string{" "})
	lane06AdbRefuse(t, err, kindNeedsArg, "emulator console command")
	_, err = runAdbReboot("dev", []string{"explode"})
	lane06AdbRefuse(t, err, kindBadArg, "not a reboot mode")
}

func TestAdbNetAndStateReachFakeToolWithExactArgs(t *testing.T) {
	rtFakeTool(t, "adb", `printf 'ran:%s\n' "$*"`)
	cases := []struct {
		name, op, target string
		args             []string
		wantArgs         []string
	}{
		{"forward prefix", "adb_forward_add", "8080", []string{"90"}, []string{"forward", "tcp:8080", "90"}},
		{"reverse prefix", "adb_reverse_add", "9000", []string{"host"}, []string{"reverse", "tcp:9000", "host"}},
		{"server default", "adb_server", "", nil, []string{"start-server"}},
		{"tcpip", "adb_tcpip", "dev", []string{"5555"}, []string{"tcpip", "5555"}},
		{"reboot recovery", "adb_reboot", "dev", []string{"recovery"}, []string{"reboot", "recovery"}},
		{"reboot bare", "adb_reboot", "dev", nil, []string{"reboot"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, err := runExtOp(c.op, c.target, c.args)
			if err != nil {
				t.Fatalf("%s: %v", c.op, err)
			}
			out, ok := v.(extOut)
			if !ok {
				t.Fatalf("%s = %T, want extOut", c.op, v)
			}
			if out.Tool != "adb" || strings.Join(out.Args, " ") != strings.Join(c.wantArgs, " ") {
				t.Fatalf("tool/args = %q/%v, want adb/%v", out.Tool, out.Args, c.wantArgs)
			}
			if !strings.Contains(out.Output, "ran:") || len(out.Lines) == 0 {
				t.Fatalf("fake adb output lost: %q", out.Output)
			}
		})
	}
}
