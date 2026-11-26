package main

// Issue 10: fake-apktool tests for the three apktool items that had none
// (install_framework, lib, publicize_resources). A /bin/sh shim on PATH proves
// the exact argv lrecon assembled; no real apktool or JVM is involved.

import (
	"strings"
	"testing"
)

func TestIssue10ApktoolFakeOps(t *testing.T) {
	rtFakeTool(t, "apktool", `printf 'ran:%s\n' "$*"`)
	cases := []struct {
		name string
		op   string
		path string
		args []string
		want []string
	}{
		{"install_framework", "apktool_install_framework", "framework.apk", nil,
			[]string{"if", "framework.apk"}},
		{"install_framework_args", "apktool_install_framework", "framework.apk", []string{"-p", "fw"},
			[]string{"if", "framework.apk", "-p", "fw"}},
		{"publicize_resources", "apktool_publicize_resources", "resources.arsc", nil,
			[]string{"pr", "resources.arsc"}},
		{"publicize_resources_args", "apktool_publicize_resources", "resources.arsc", []string{"-v"},
			[]string{"pr", "resources.arsc", "-v"}},
		{"lib", "apktool_lib", "app.apk", []string{"com.example:string/foo"},
			[]string{"d", "-o", "<dir>", "-l", "com.example:string/foo", "app.apk"}},
		{"lib_args", "apktool_lib", "app.apk", []string{"com.example:string/foo", "-f"},
			[]string{"d", "-o", "<dir>", "-l", "com.example:string/foo", "app.apk", "-f"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, err := runExtOp(c.op, c.path, c.args)
			if err != nil {
				t.Fatalf("%s: %v", c.op, err)
			}
			out, ok := v.(extOut)
			if !ok {
				t.Fatalf("%s = %T, want extOut", c.op, v)
			}
			if out.Tool != "apktool" {
				t.Fatalf("%s tool = %q, want apktool", c.op, out.Tool)
			}
			if len(out.Args) != len(c.want) {
				t.Fatalf("%s args = %v, want %v", c.op, out.Args, c.want)
			}
			for i := range c.want {
				if strings.HasPrefix(c.want[i], "<dir>") {
					if !strings.HasSuffix(out.Args[i], "/out") {
						t.Fatalf("%s arg %d = %q, want a dir ending in /out", c.op, i, out.Args[i])
					}
					continue
				}
				if out.Args[i] != c.want[i] {
					t.Fatalf("%s arg %d = %q, want %q (all: %v)", c.op, i, out.Args[i], c.want[i], out.Args)
				}
			}
			// The shim prints its own argv, so this proves it was invoked with
			// the same arguments lrecon reports.
			if !strings.Contains(out.Output, "ran:"+strings.Join(out.Args, " ")) || len(out.Lines) == 0 {
				t.Fatalf("%s output = %q, want the shim's argv line", c.op, out.Output)
			}
		})
	}
}

func TestIssue10ApktoolFakeLibNeedsPKGFile(t *testing.T) {
	rtNoTools(t)
	if _, err := apktoolLib("app.apk", nil); err == nil || !strings.Contains(err.Error(), "apktool_lib needs PKG:FILE") {
		t.Fatalf("apktool_lib no arg = %v, want the PKG:FILE refusal", err)
	}
}

func TestIssue10ApktoolFakeMissingTool(t *testing.T) {
	rtNoTools(t)
	for _, op := range []string{"apktool_install_framework", "apktool_publicize_resources"} {
		if _, err := runExtOp(op, "target.bin", nil); err == nil || !strings.Contains(err.Error(), "apktool not installed") {
			t.Fatalf("%s without apktool = %v, want the not-installed refusal", op, err)
		}
	}
}
