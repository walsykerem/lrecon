package main

// Regression: inspect_apk_signature on a non-APK (Mach-O) target lied with
// ok/Signed:false because the zip.OpenReader error was ignored. It must
// answer bad_arg now.

import (
	"strings"
	"testing"
)

func TestInspectApkSignatureRejectsNonAPK(t *testing.T) {
	p := opStaticFile(t, "target.bin", []byte{0xcf, 0xfa, 0xed, 0xfe, 0x00, 0x00, 0x00, 0x00})
	if _, err := runOp("inspect_apk_signature", p); err == nil {
		t.Fatal("non-APK target accepted, want bad_arg")
	} else if got := classify(err.Error()); got != kindBadArg {
		t.Fatalf("kind = %s, want %s: %v", got, kindBadArg, err)
	} else if !strings.Contains(err.Error(), "not a zip/apk") {
		t.Fatalf("message %q does not name the format", err)
	}
}
