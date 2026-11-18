package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type objcSect struct {
	name string
	data []byte
}

// objcMachO builds the smallest Mach-O this reader understands: one __DATA
// segment holding exactly the sections given. Addresses equal file offsets, the
// MH_OBJECT convention, so no segment mapping is needed to read them.
func objcMachO(sects []objcSect) []byte {
	const hdr, segCmd, sectHdr = 32, 72, 80
	cmdSize := segCmd + sectHdr*len(sects)
	offs := make([]int, len(sects))
	total := hdr + cmdSize
	for i, s := range sects {
		offs[i] = total
		total = (total + len(s.data) + 7) &^ 7
	}
	b := make([]byte, total)
	binary.LittleEndian.PutUint32(b[0:], 0xfeedfacf)
	binary.LittleEndian.PutUint32(b[4:], 0x0100000c)       // arm64
	binary.LittleEndian.PutUint32(b[12:], 1)               // MH_OBJECT
	binary.LittleEndian.PutUint32(b[16:], 1)               // ncmds
	binary.LittleEndian.PutUint32(b[20:], uint32(cmdSize)) // sizeofcmds

	seg := b[hdr:]
	binary.LittleEndian.PutUint32(seg[0:], 0x19) // LC_SEGMENT_64
	binary.LittleEndian.PutUint32(seg[4:], uint32(cmdSize))
	copy(seg[8:24], "__DATA")
	binary.LittleEndian.PutUint64(seg[32:], uint64(total)) // vmsize
	binary.LittleEndian.PutUint64(seg[48:], uint64(total)) // filesize
	binary.LittleEndian.PutUint32(seg[64:], uint32(len(sects)))
	for i, s := range sects {
		sc := seg[segCmd+i*sectHdr:]
		copy(sc[0:16], s.name)
		copy(sc[16:32], "__DATA")
		binary.LittleEndian.PutUint64(sc[32:], uint64(offs[i])) // addr
		binary.LittleEndian.PutUint64(sc[40:], uint64(len(s.data)))
		binary.LittleEndian.PutUint32(sc[48:], uint32(offs[i]))
		copy(b[offs[i]:], s.data)
	}
	return b
}

// objcRun writes b to a temp file and runs this reader on it. Other post
// readers (mangling and friends) are not involved, so the assertions stay about
// objc only.
func objcRun(t *testing.T, b []byte) Digest {
	t.Helper()
	path := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	d := Digest{Path: path, Kind: "macho", Format: "macho"}
	inspectObjC(path, &d)
	return d
}

func objcCaps(d Digest) []string {
	var out []string
	for _, c := range d.Capabilities {
		if strings.HasPrefix(c, "objc:") {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

func TestObjcNamesAndCounts(t *testing.T) {
	classlist := make([]byte, 16) // two 8-byte pointers, values unused
	b := objcMachO([]objcSect{
		{"__objc_classname", []byte("NSWindow\x00NSObject\x00")},
		{"__objc_methname", []byte("description\x00initWithFrame:\x00")},
		{"__objc_methtype", []byte("v16@0:8\x00")},
		{"__objc_classlist", classlist},
	})
	d := objcRun(t, b)
	want := []string{
		"objc:classlist=2",
		"objc:classname=NSObject",
		"objc:classname=NSWindow",
		"objc:classnames=2",
		"objc:methnames=2",
		"objc:method=description",
		"objc:method=initWithFrame:",
		"objc:methtypes=1",
		"objc:type=v16@0:8",
	}
	if got := objcCaps(d); !equalStrings(got, want) {
		t.Errorf("Capabilities = %v, want %v", got, want)
	}
	if d.Coverage == nil || d.Coverage.Parsed != 5 || d.Coverage.Skipped != 0 {
		t.Errorf("Coverage = %+v, want parsed:5 skipped:0", d.Coverage)
	}
	if d.Kind != "macho" {
		t.Errorf("Kind = %q, post reader must not change it", d.Kind)
	}
}

func TestObjcEmptySectionsAnswerZero(t *testing.T) {
	b := objcMachO([]objcSect{
		{"__objc_classname", nil},
		{"__objc_methname", nil},
		{"__objc_methtype", nil},
		{"__objc_classlist", nil},
	})
	d := objcRun(t, b)
	want := []string{"objc:classlist=0", "objc:classnames=0", "objc:methnames=0", "objc:methtypes=0"}
	if got := objcCaps(d); !equalStrings(got, want) {
		t.Errorf("Capabilities = %v, want %v", got, want)
	}
	if len(d.Skipped) != 0 {
		t.Errorf("Skipped = %v, a present-but-empty section is not a refusal", d.Skipped)
	}
	if d.Coverage != nil {
		t.Errorf("Coverage = %+v, want none: no name block was read", d.Coverage)
	}
}

// A file that was built with Objective-C but lost the name sections is the one
// case that must refuse by name instead of returning an empty answer.
func TestObjcMissingNameSectionsRefused(t *testing.T) {
	b := objcMachO([]objcSect{{"__objc_imageinfo", make([]byte, 8)}})
	d := objcRun(t, b)
	if len(d.Skipped) != 1 || d.Skipped[0].Reason != objcNoSections {
		t.Fatalf("Skipped = %v, want one %s", d.Skipped, objcNoSections)
	}
	if len(d.Capabilities) != 0 {
		t.Errorf("Capabilities = %v, want none", d.Capabilities)
	}
}

// A C or Swift Mach-O carries no ObjC marker: the reader must stay silent, or
// every Mach-O digest would gain a false "no objc" line.
func TestObjcSilentWithoutObjcEvidence(t *testing.T) {
	b := objcMachO([]objcSect{{"__cstring", []byte("hello\x00")}})
	d := objcRun(t, b)
	if len(d.Capabilities) != 0 || len(d.Skipped) != 0 || d.Coverage != nil {
		t.Errorf("Capabilities = %v, Skipped = %v, Coverage = %+v, want all empty", d.Capabilities, d.Skipped, d.Coverage)
	}
}

func TestObjcTruncatedSectionRefused(t *testing.T) {
	b := objcMachO([]objcSect{
		{"__objc_classname", []byte("Tiny\x00")},
		{"__objc_methname", []byte("run\x00")},
	})
	// Claim a size past EOF for the class name blob only.
	i := bytes.Index(b, []byte("__objc_classname"))
	if i < 0 {
		t.Fatal("fixture lost its section header")
	}
	binary.LittleEndian.PutUint64(b[i+40:], 4096)

	d := objcRun(t, b)
	var truncated bool
	for _, s := range d.Skipped {
		truncated = truncated || s.Reason == objcTruncated
	}
	if !truncated {
		t.Fatalf("Skipped = %v, want %s", d.Skipped, objcTruncated)
	}
	for _, c := range d.Capabilities {
		if strings.HasPrefix(c, "objc:classnames") || strings.HasPrefix(c, "objc:classname=") {
			t.Errorf("Capability %q counts an unreadable section", c)
		}
	}
	if d.Coverage == nil || d.Coverage.Parsed != 1 {
		t.Errorf("Coverage = %+v, want parsed:1 from the readable methname section", d.Coverage)
	}
}

func TestObjcNameCapRefuses(t *testing.T) {
	var sb strings.Builder
	for i := 0; i <= objcMaxNames; i++ {
		sb.WriteString("n")
		sb.WriteString(strconv.Itoa(i))
		sb.WriteString("\x00")
	}
	b := objcMachO([]objcSect{{"__objc_classname", []byte(sb.String())}})
	d := objcRun(t, b)

	capped, n := false, 0
	for _, s := range d.Skipped {
		capped = capped || s.Reason == objcNameCap
	}
	for _, c := range d.Capabilities {
		if strings.HasPrefix(c, "objc:classnames=") && c != "objc:classnames="+strconv.Itoa(objcMaxNames) {
			t.Errorf("count = %q, want the cap %d", c, objcMaxNames)
		}
		if strings.HasPrefix(c, "objc:classname=") {
			n++
		}
	}
	if !capped {
		t.Errorf("Skipped = %v, want %s past the cap", d.Skipped, objcNameCap)
	}
	if n != objcMaxNames {
		t.Errorf("emitted %d class names, want the cap %d", n, objcMaxNames)
	}
}

func TestObjcNonMachONoPanic(t *testing.T) {
	d := objcRun(t, []byte("hello, not a mach-o\n"))
	if len(d.Capabilities) != 0 || len(d.Skipped) != 0 {
		t.Errorf("Capabilities = %v, Skipped = %v, want none", d.Capabilities, d.Skipped)
	}
	d = Digest{Kind: "unknown"}
	dispatchPost("/does/not/exist", []byte("hello"), 18, &d)
	if d.Kind != "unknown" {
		t.Errorf("Kind = %q, want unknown", d.Kind)
	}
}

// The reader is registered as a post reader: a Mach-O target must pick it up
// through dispatchPost and keep the kind Mach-O owns.
func TestObjcRegisteredAsPostReader(t *testing.T) {
	b := objcMachO([]objcSect{{"__objc_classname", []byte("Registered\x00")}})
	path := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	d := Digest{Kind: "macho"}
	dispatchPost(path, b, int64(len(b)), &d)
	if d.Kind != "macho" {
		t.Errorf("Kind = %q, want macho", d.Kind)
	}
	if !strings.Contains(strings.Join(d.Capabilities, ","), "objc:classname=Registered") {
		t.Errorf("Capabilities = %v, want objc:classname=Registered from dispatchPost", d.Capabilities)
	}
}

func TestObjcWriteFixture(t *testing.T) {
	out := os.Getenv("LRECON_OBJC_FIXTURE")
	if out == "" {
		t.Skip("fixture path not requested")
	}
	b := objcMachO([]objcSect{
		{"__objc_classname", []byte("NSWindow\x00NSObject\x00")},
		{"__objc_methname", []byte("description\x00initWithFrame:\x00")},
		{"__objc_methtype", []byte("v16@0:8\x00")},
		{"__objc_classlist", make([]byte, 16)},
	})
	if err := os.WriteFile(out, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// clang keeps protocol names in the classname pool, so a name there is a
// section entry, never a class claim: `@protocol Drawable` must not surface as
// `objc:class=Drawable`.
func TestObjcClassnamePoolIsNotClasses(t *testing.T) {
	b := objcMachO([]objcSect{
		{"__objc_classname", []byte("Shape\x00Drawable\x00")},
		{"__objc_classlist", make([]byte, 16)},
	})
	d := objcRun(t, b)
	caps := strings.Join(objcCaps(d), ",")
	if !strings.Contains(caps, "objc:classname=Drawable") || !strings.Contains(caps, "objc:classname=Shape") {
		t.Fatalf("Capabilities = %v, want the two pool entries", d.Capabilities)
	}
	if strings.Contains(caps, "objc:class=") {
		t.Fatalf("Capabilities = %v, a pool entry was claimed as a class", d.Capabilities)
	}
}
