package main

import (
	"os"
	"strings"
	"testing"
)

// One realistic spelling per family, plus the shapes each family really has.
func TestManglingFamilyOf(t *testing.T) {
	cases := []struct {
		sym  string
		want string
	}{
		// Itanium C++
		{"_ZN3Foo3barEv", "itanium"},
		{"_ZNK3Foo3barEv", "itanium"},
		{"_ZNSt6vectorIiSaIiEE9push_backERKi", "itanium"},
		{"_ZThn8_N3Foo3barEv", "itanium"},
		{"_ZTv0_n24_N3Foo3barEv", "itanium"},
		{"_ZTV3Foo", "itanium"},
		{"_Z3foov", "itanium"},
		{"_ZdlPv", "itanium"},
		{"_ZSt4cout", "itanium"},
		{"__ZN3Foo3barEv", "itanium"}, // Mach-O leading underscore

		// MSVC C++
		{"?a@@YAHD@Z", "msvc"},
		{"?foo@@YAHH@Z", "msvc"},
		{"??2@YAPEAX_K@Z", "msvc"},
		{"??_7Foo@@6B@", "msvc"},

		// Rust legacy and v0, taken from real rustc output
		{"_ZN4core3fmt9Formatter3pad17h0123456789abcdefE", "rust-legacy"},
		{"__ZN4core3fmt9Formatter3pad17h0123456789abcdefE", "rust-legacy"},
		{"_RNvCsciEypvKo6Eu_6subtle9black_box", "rust-v0"},
		{"_RINvMNtCs7D6vsR61zFR_6rustup9toolchainNtB3_9Toolchain14create_commandRe", "rust-v0"},
		{"__RINvMNtCs7D6vsR61zFR_6rustup8settingsNtB3_12SettingsFile4withNtNtB5_4dist11TargetTupleECsepRZuQ4vWst_11rustup_init", "rust-v0"},
		{"_RNvNtCs1234_4core3fmt8get_count", "rust-v0"},

		// Go
		{"main.main", "go"},
		{"internal/abi.Type", "go"},
		{"runtime.(*mheap).alloc", "go"},
		{"github.com/cli/cli/v2/pkg/cmd/root.NewCmdRoot", "go"},
		{"type:.eq.main.T", "go"},
		{"go:buildid", "go"},
		{"runtime.gcbits·0", "go"},

		// Swift
		{"$s4main3fooyyF", "swift"},
		{"_$s4main3fooyyF", "swift"},
		{"$sSo8NSObjectC", "swift"},

		// Objective-C
		{"-[NSObject description]", "objc"},
		{"+[Foo bar:baz:]", "objc"},
		{"-[Foo(Cat) sel]", "objc"},

		// Traps: decoration without a full shape is not a family.
		{"_Z", ""},
		{"_Zfoo", ""},
		{"_ZNK", ""},
		{"_R", ""},
		{"_RN", ""},
		{"_Rfoo", ""},
		{"_RNvC3std3foo", ""},                  // no crate root framing
		{"_RNvCsciEypvKo6Eu_6subtleB999_", ""}, // backref past the cursor
		{"_RNvCsciEypvKo6Eu_6subtleu12X", ""},  // escape without terminator
		{"?foo", ""},
		{"_main", ""},
		{"printf", ""},
		{"g_object_new", ""},
		{"$s", ""},
		{"-[NSObject", ""},
		{"OBJC_CLASS_$_Foo", ""},

		// Traps: C/asm names on Mach-O carry dots and a leading underscore.
		// These are exactly the names that made a loose pkg.Func rule
		// report go=22 on a Rust binary.
		{"_aws_lc_0_44_0_BN_value_one_do_init.kOneLimbs", ""},
		{"_calc_tag.padding", ""},
		{"_get_mem_info.size", ""},
		{"_ZSTD_overlapCopy8.dec32table", ""},
		{".Lxts_dec_big_size", ""},
		{"lzma_decode.next_state", ""},
		{"", ""},
	}
	for _, tc := range cases {
		got, shape := manglingFamily(tc.sym)
		if got != tc.want {
			t.Errorf("manglingFamily(%q) = %q (%s), want %q", tc.sym, got, shape, tc.want)
		}
		if got != "" && shape == "" {
			t.Errorf("manglingFamily(%q) matched %q with no shape witness", tc.sym, got)
		}
	}
}

func TestManglingFamiliesCount(t *testing.T) {
	cases := []struct {
		name    string
		symbols []string
		want    string
		count   int
	}{
		{
			name:    "itanium",
			symbols: []string{"_ZN3Foo3barEv", "_ZTV3Foo", "_Z3bazv", "_main"},
			want:    "itanium",
			count:   3,
		},
		{
			name:    "msvc",
			symbols: []string{"?a@@YAHD@Z", "?foo@@YAHH@Z", "??2@YAPEAX_K@Z"},
			want:    "msvc",
			count:   3,
		},
		{
			name: "rust-legacy",
			symbols: []string{
				"_ZN4core3fmt9Formatter3pad17h0123456789abcdefE",
				"_ZN3std2io5Write9write_all17hfedcba9876543210E.llvm.12345",
				"_ZN5alloc5alloc17h0011223344556677E",
			},
			want:  "rust-legacy",
			count: 3,
		},
		{
			name: "rust-v0",
			symbols: []string{
				"_RNvCsciEypvKo6Eu_6subtle9black_box",
				"_RNvNtCs1234_4core3fmt8get_count",
				"_RNCNvCs1234_4core3fmt5write0",
			},
			want:  "rust-v0",
			count: 3,
		},
		{
			name:    "go",
			symbols: []string{"main.main", "runtime.(*mheap).alloc", "type:.eq.main.T", "_printf"},
			want:    "go",
			count:   3,
		},
		{
			name:    "swift",
			symbols: []string{"$s4main3fooyyF", "_$s4main3baryyF", "$sSo8NSObjectC"},
			want:    "swift",
			count:   3,
		},
		{
			name:    "objc",
			symbols: []string{"-[NSObject description]", "+[Foo bar:baz:]", "-[Foo(Cat) sel]"},
			want:    "objc",
			count:   3,
		},
	}
	for _, tc := range cases {
		counts := manglingCounts(tc.symbols)
		if counts[tc.want] != tc.count {
			t.Errorf("%s: count = %d, want %d (%v)", tc.name, counts[tc.want], tc.count, counts)
		}
		for fam, n := range counts {
			if fam != tc.want {
				t.Errorf("%s: %q also matched %d symbols", tc.name, fam, n)
			}
		}
	}
}

// The Rust legacy family is defined by the 16-hex-digit hash suffix; a wrong
// width is not legacy evidence (it still looks like Itanium, which is honest).
func TestManglingRustLegacyHashWidth(t *testing.T) {
	for _, tc := range []struct {
		sym  string
		want bool
	}{
		{"_ZN4core3fmt9Formatter3pad17h0123456789abcdefE", true},
		{"_ZN4core3fmt9Formatter3pad17h0123456789abcdeE", false},   // 15 hex
		{"_ZN4core3fmt9Formatter3pad17h0123456789abcdef0E", false}, // 17 hex
		{"_ZN4core3fmt9Formatter3pad17h0123456789ABCDEFE", false},  // uppercase
		{"_Z3foov", false},
	} {
		got, _ := manglingFamily(tc.sym)
		if (got == "rust-legacy") != tc.want {
			t.Errorf("manglingFamily(%q) = %q, want rust-legacy=%v", tc.sym, got, tc.want)
		}
	}
}

// Two witnesses stay a hint: the threshold is the only thing that promotes a
// family to a capability.
func TestManglingThreshold(t *testing.T) {
	caps, _, below := manglingDecision(map[string]int{"itanium": 2}, 2)
	if len(caps) != 0 {
		t.Fatalf("two matches became %v", caps)
	}
	if !strings.Contains(below, "itanium=2") {
		t.Fatalf("under-threshold detail lost the count: %q", below)
	}
	caps, note, _ := manglingDecision(map[string]int{"itanium": 3, "go": 1}, 4)
	if len(caps) != 1 || caps[0] != "mangling:itanium=3" {
		t.Fatalf("caps = %v, want only mangling:itanium=3", caps)
	}
	if !strings.Contains(note, "itanium=3") || !strings.Contains(note, "go=1") {
		t.Fatalf("note dropped a counted family: %q", note)
	}
	if caps, _, _ := manglingDecision(map[string]int{"msvc": 0}, 10); len(caps) != 0 {
		t.Fatalf("zero counts produced %v", caps)
	}
}

// End to end: /bin/ls is plain C, so no family may be invented for it.
func TestManglingProbeLs(t *testing.T) {
	if _, err := os.Stat("/bin/ls"); err != nil {
		t.Skipf("/bin/ls unavailable: %v", err)
	}
	d, err := Probe("/bin/ls")
	if err != nil {
		t.Fatalf("Probe(/bin/ls): %v", err)
	}
	for _, c := range d.Capabilities {
		if strings.HasPrefix(c, "mangling:") && c != "mangling:unknown" {
			t.Fatalf("C binary invented a mangling family: %q (all: %v)", c, d.Capabilities)
		}
	}
}

// BenchmarkManglingFamily covers the per-symbol classifier on a name mix shaped
// like a real C++/Rust symbol table: mostly plain C, plus the families and the
// LTO `.llvm.` suffixes a link-time-optimized build carries.
func BenchmarkManglingFamily(b *testing.B) {
	names := []string{
		"_ZN4core3fmt9Formatter3pad17h0123456789abcdefE",
		"_RNvCsciEypvKo6Eu_6subtle9black_box",
		"__ZN3Foo3barEv",
		"_ZNK3Foo3barEv",
		"?foo@@YAHH@Z",
		"_Z3foov",
		"__Z3foov.llvm.1234567890",
		"_RNvNtCs1234_4core3fmt8get_count.llvm.42",
		"main",
		"malloc",
		"objc_msgSend",
		"-[NSObject description]",
	}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		manglingFamily(names[i%len(names)])
		i++
	}
}

// The LTO suffix is stripped before family matching, and only the anchored
// `.llvm.<digits>` shape is a suffix. The guards that skip the regex for names
// without it must not change any of that.
func TestManglingLTOSuffix(t *testing.T) {
	for _, name := range []string{"_Z3foov", "_ZN4core3fmt9Formatter3pad17h0123456789abcdefE", "_RNvCsciEypvKo6Eu_6subtle9black_box"} {
		bare, bshape := manglingFamily(name)
		if bare == "" {
			t.Fatalf("%s matched no family", name)
		}
		got, gshape := manglingFamily(name + ".llvm.1234567890")
		if got != bare || gshape != bshape {
			t.Fatalf("%s.llvm.1234 = %s/%s, want %s/%s", name, got, gshape, bare, bshape)
		}
	}
	// A non-numeric tail is not stripped, so the name is judged as written.
	if fam, _ := manglingFamily("_Z3foov.llvm.x"); fam != "itanium" {
		t.Fatalf("_Z3foov.llvm.x = %q, want itanium (suffix must be .llvm.<digits>)", fam)
	}
	// ObjC and Go leads are gated on their first byte; the gates must not
	// invent or lose a family.
	if fam, _ := manglingFamily("-[NSObject description]"); fam != "objc" {
		t.Fatalf("ObjC method = %q, want objc", fam)
	}
	if fam, _ := manglingFamily("x[Foo bar]"); fam != "" {
		t.Fatalf("no polarity byte = %q, want no family", fam)
	}
	if fam, shape := manglingFamily("pkg.Foo"); fam != "go" || shape != "pkg-func" {
		t.Fatalf("pkg.Foo = %s/%s, want go/pkg-func", fam, shape)
	}
	if fam, _ := manglingFamily("Foo.Bar"); fam != "" {
		t.Fatalf("Foo.Bar = %q, want no family (package lead is lowercase)", fam)
	}
}
