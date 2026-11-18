package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The device shell re-splits the string adb joins from its argv, so a target
// path with a space must reach ls as one quoted word; unquoted it became two
// arguments and the op failed with "No such file or directory" (A11 lane).
func TestA11ListADBDirectoryQuotesTarget(t *testing.T) {
	seen := filepath.Join(t.TempDir(), "args.txt")
	rtFakeTool(t, "adb", `if [ "$3" = "shell" ]; then
  printf '%s\n' "$*" > `+seen+`
  printf 'total 0\ndrwxr-xr-x  2 root root 4096 2024-01-01 12:00 My Files\n'
  exit 0
fi
`+rtOneDevice)
	v, err := runOp("list_adb_directory", "/sdcard/My Files")
	if err != nil {
		t.Fatal(err)
	}
	got := v.(rtDirListing)
	if got.Path != "/sdcard/My Files" || len(got.Entries) != 1 || got.Entries[0].Name != "My Files" || !got.Entries[0].IsDir {
		t.Fatalf("listing = %+v", got)
	}
	b, err := os.ReadFile(seen)
	if err != nil {
		t.Fatal(err)
	}
	if s := strings.TrimSpace(string(b)); !strings.HasSuffix(s, "'/sdcard/My Files'") {
		t.Fatalf("device shell saw %q, want the path as one quoted word", s)
	}
}

func TestA11AdbShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"/sdcard/Download":    "'/sdcard/Download'",
		"/sdcard/My Files":    "'/sdcard/My Files'",
		"/sdcard/it's here":   `'/sdcard/it'\''s here'`,
		"/sdcard/$(rm -rf x)": "'/sdcard/$(rm -rf x)'",
	} {
		if got := adbShellQuote(in); got != want {
			t.Errorf("adbShellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

// jsonShape returns the compact JSON of one op result, so a test can assert the
// wire shape ([] and not null) the way a machine caller sees it.
func jsonShape(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestA11ListADBFeaturesEmptyIsArray(t *testing.T) {
	rtFakeTool(t, "adb", `if [ "$1" = "host-features" ]; then printf ' , ,\n'; exit 0; fi
`+rtOneDevice)
	v, err := runOp("list_adb_features", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := v.(rtADBFeatures); got.Count != 0 || got.Features == nil {
		t.Fatalf("features = %+v, want an empty slice", got)
	}
	if s := jsonShape(t, v); !strings.Contains(s, `"features":[]`) {
		t.Fatalf("json = %s, want an empty array and not null", s)
	}
}

func TestA11ListADBServicesHeaderOnlyIsEmptyArray(t *testing.T) {
	rtFakeTool(t, "adb", `case "$*" in
  "devices"|"devices -l") printf 'List of devices attached\nR58M\tdevice product:beyond1lte\n' ;;
  "shell dumpsys -l") printf 'Currently running services:\n' ;;
esac
`)
	v, err := runOp("list_adb_services", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := v.(rt2AdbServices); got.Count != 0 || got.Services == nil {
		t.Fatalf("services = %+v, want an empty slice", got)
	}
	if s := jsonShape(t, v); !strings.Contains(s, `"services":[]`) {
		t.Fatalf("json = %s, want an empty array and not null", s)
	}
}

// The map literal starts projects/searched as empty arrays; a nil slice
// overwrote them with null, so a caller saw the wrong type (A11 lane).
func TestA11ListCutterSessionsEmptyIsArray(t *testing.T) {
	t.Setenv("HOME", "")
	v, err := runOp("list_cutter_sessions", "")
	if err != nil {
		t.Fatal(err)
	}
	s := jsonShape(t, v)
	for _, want := range []string{`"projects":[]`, `"searched":[]`} {
		if !strings.Contains(s, want) {
			t.Errorf("json = %s, want %s", s, want)
		}
	}
}

func TestA11ListOpsWithNeedsRefuseEmptyTarget(t *testing.T) {
	for _, name := range []string{"list_adb_directory", "list_architectures", "list_browser_targets"} {
		if _, err := runOp(name, ""); err == nil || !strings.Contains(err.Error(), "needs a target path") {
			t.Errorf("%s on an empty target = %v, want a needs-target refusal", name, err)
		}
	}
}
