package main

// Issue #8: the 11 adb ext ops that had no test. Each one is a thin argv
// builder over adbRun/extAdb, so the proof is the exact argv a fake adb on
// PATH receives, plus the refusals that must fire before the tool is touched.

import (
	"errors"
	"strings"
	"testing"
)

func issue8AdbRefusal(t *testing.T, err error, wantKind errorKind, wantMsg string) {
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

func TestIssue8AdbOpsArgValidationBeforeTool(t *testing.T) {
	rtNoTools(t)
	_, err := adbForwardRemove("", nil)
	issue8AdbRefusal(t, err, kindNeedsArg, "tcp:LOCAL")
	_, err = adbReverseRemove("", nil)
	issue8AdbRefusal(t, err, kindNeedsArg, "tcp:REMOTE")
	_, err = adbKeygen("", nil)
	issue8AdbRefusal(t, err, kindNeedsArg, "FILE")
}

func TestIssue8AdbOpsReachFakeToolWithExactArgs(t *testing.T) {
	rtFakeTool(t, "adb", `printf 'ran:%s\n' "$*"`)
	cases := []struct {
		name, op, target string
		args             []string
		wantArgs         []string
	}{
		{"root", "adb_root", "", nil, []string{"root"}},
		{"unroot", "adb_unroot", "", nil, []string{"unroot"}},
		{"usb", "adb_usb", "", nil, []string{"usb"}},
		{"remount", "adb_remount", "", nil, []string{"remount"}},
		{"disable verity", "adb_disable_verity", "", nil, []string{"disable-verity"}},
		{"enable verity", "adb_enable_verity", "", nil, []string{"enable-verity"}},
		{"reverse list", "adb_reverse_list", "", nil, []string{"reverse", "--list"}},
		{"jdwp", "adb_jdwp", "R58M", nil, []string{"jdwp"}},
		{"forward remove prefix", "adb_forward_remove", "8080", nil, []string{"forward", "--remove", "tcp:8080"}},
		{"forward remove tcp", "adb_forward_remove", "tcp:8080", nil, []string{"forward", "--remove", "tcp:8080"}},
		{"reverse remove prefix", "adb_reverse_remove", "9000", nil, []string{"reverse", "--remove", "tcp:9000"}},
		{"reverse remove tcp", "adb_reverse_remove", "tcp:9000", nil, []string{"reverse", "--remove", "tcp:9000"}},
		{"keygen", "adb_keygen", " adbkey ", nil, []string{"keygen", "adbkey"}},
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
			wantLine := "ran:" + strings.Join(c.wantArgs, " ")
			if !strings.Contains(out.Output, wantLine) || len(out.Lines) == 0 {
				t.Fatalf("fake adb output lost: %q", out.Output)
			}
			if strings.TrimSpace(out.Lines[0]) != wantLine {
				t.Fatalf("first line = %q, want %q", out.Lines[0], wantLine)
			}
		})
	}
}

func TestIssue8AdbOpsMissingToolIsNoEngine(t *testing.T) {
	rtNoTools(t)
	_, err := runExtOp("adb_root", "", nil)
	issue8AdbRefusal(t, err, kindNoEngine, "platform-tools")
}
