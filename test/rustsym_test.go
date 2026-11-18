package main

import (
	"strings"
	"testing"
)

// Every expected string below is the alternate spelling printed by
// rustc-demangle 0.1.26 for a symbol taken from a real rustc 1.92 binary
// (legacy and v0), not a hand-guessed name.

func TestRustLegacyDemangle(t *testing.T) {
	tests := []struct{ in, want string }{
		{
			"_ZN14rustc_demangle12try_demangle17h648854d1156fd625E",
			"rustc_demangle::try_demangle",
		},
		{
			"_ZN104_$LT$core..iter..sources..from_fn..FromFn$LT$F$GT$$u20$as$u20$core..iter..traits..iterator..Iterator$GT$4next17h5e84480713b38794E",
			"<core::iter::sources::from_fn::FromFn<F> as core::iter::traits::iterator::Iterator>::next",
		},
		{
			"_ZN14rustc_demangle2v07Printer10print_type28_$u7b$$u7b$closure$u7d$$u7d$17h7931f6e232bd6a6fE",
			"rustc_demangle::v0::Printer::print_type::{{closure}}",
		},
		{
			"_ZN4core3ptr107drop_in_place$LT$core..pin..Pin$LT$alloc..boxed..Box$LT$std..sys..pal..unix..sync..mutex..Mutex$GT$$GT$$GT$17hb95559412fbb8a0aE",
			"core::ptr::drop_in_place<core::pin::Pin<alloc::boxed::Box<std::sys::pal::unix::sync::mutex::Mutex>>>",
		},
		{
			// No hash at all is still a valid legacy name; the hash is an
			// optional last element, not part of the path.
			"_ZN5myapp3runE",
			"myapp::run",
		},
		{
			// `$C$` is the escaped comma; element escaping is textual only.
			"_ZN5a$C$bE",
			"a,b",
		},
	}
	for _, tc := range tests {
		got, ok := rustLegacyDemangle(tc.in)
		if !ok || got != tc.want {
			t.Errorf("rustLegacyDemangle(%q) = %q, %v; want %q, true", tc.in, got, ok, tc.want)
		}
	}
}

func TestRustLegacyRefusals(t *testing.T) {
	for _, in := range []string{
		"",
		"_ZN",
		"_ZN3foo3bar17h0123456789abcdefE.0", // suffix is not part of the name
		"_ZN5abcE",                          // element longer than the rest
		"_ZN3foo",                           // no terminating E
		"_ZNx3fooE",                         // length is not decimal
		"std::foo",                          // not mangled at all
	} {
		if got, ok := rustLegacyDemangle(in); ok {
			t.Errorf("rustLegacyDemangle(%q) = %q, want refusal", in, got)
		}
	}
}

func TestRustV0Demangle(t *testing.T) {
	tests := []struct{ in, want string }{
		{
			"_RNvCsiGVaDesi5rv_7___rustc10rust_panic",
			"__rustc::rust_panic",
		},
		{
			// A backref (B5_) to the std path segment earlier in the name.
			"_RNvXsZ_NtCsiThrkg7suPy_3std7processuNtB5_11Termination6reportCs8T06j01h6Re_4bref",
			"<() as std::process::Termination>::report",
		},
		{
			// Top-level path is a value, so I prints `::<...>`; N adds the
			// special namespace suffix.
			"_RNCINvNtCsiThrkg7suPy_3std2rt10lang_startuE0Cs8T06j01h6Re_4bref",
			"std::rt::lang_start::<()>::{closure#0}",
		},
		{
			// Y = impl with a fn-pointer self type and no `as` path.
			"_RNvYFEuINtNtNtCskzPJi2J8k3N_4core3ops8function6FnOnceuE9call_onceCs8T06j01h6Re_4bref",
			"<fn() as core::ops::function::FnOnce<()>>::call_once",
		},
		{
			"_RNSNvYNCINvNtCsiThrkg7suPy_3std2rt10lang_startuE0INtNtNtCskzPJi2J8k3N_4core3ops8function6FnOnceuE9call_once6vtableCs8T06j01h6Re_4bref",
			"<std::rt::lang_start<()>::{closure#0} as core::ops::function::FnOnce<()>>::call_once::{shim:vtable#0}",
		},
	}
	for _, tc := range tests {
		got, ok := rustV0Demangle(tc.in)
		if !ok || got != tc.want {
			t.Errorf("rustV0Demangle(%q) = %q, %v; want %q, true", tc.in, got, ok, tc.want)
		}
	}
}

func TestRustV0Refusals(t *testing.T) {
	for _, in := range []string{
		"",
		"_R",
		"_RNvC",          // path tag with no ident
		"_RNvC5ab",       // ident length past the end
		"_RNvC1a1b$junk", // trailing bytes are not a name we can vouch for
		"_RNvC2ab\u00e9", // non-ASCII symbol table entry
		"_RNvC4u3abc",    // punycode ident: outside the ported subset
		"_RTB_",          // backref to the tag itself, not a previous path
		// A lowercase namespace takes no `s<dis>` disambiguator (v0.rs:825):
		// the `s` belongs to no ident, so the name is malformed.
		"_RNvC1xs1_1y",
	} {
		if got, ok := rustV0Demangle(in); ok {
			t.Errorf("rustV0Demangle(%q) = %q, want refusal", in, got)
		}
	}
}

func TestRustSymClassification(t *testing.T) {
	glue := []string{
		"core::ptr::drop_in_place<alloc::string::String>",
		"core::ops::function::FnOnce::call_once{{vtable.shim}}",
		"alloc::boxed::Box<T>::drop_glue",
	}
	for _, s := range glue {
		if !rustSymGlue(s) {
			t.Errorf("rustSymGlue(%q) = false, want true", s)
		}
	}
	if rustSymGlue("myapp::drop_the_ball") {
		t.Error("rustSymGlue matched a user function without glue marker")
	}

	for _, s := range []string{
		"std::panicking::begin_panic",
		"panic_unwind::imp::panic::exception_cleanup",
		"__rustc::rust_panic",
	} {
		if !rustSymPanic(s) {
			t.Errorf("rustSymPanic(%q) = false, want true", s)
		}
	}
	// Merely containing the word is not the runtime.
	if rustSymPanic("myapp::panic_handler") {
		t.Error("rustSymPanic matched a user function named panic_handler")
	}

	for _, s := range []string{
		"myapp::main::{{closure}}",
		"std::rt::lang_start::{closure#0}",
	} {
		if !rustSymClosure(s) {
			t.Errorf("rustSymClosure(%q) = false, want true", s)
		}
	}

	if got := rustSymCrate("myapp::db::connect"); got != "myapp" {
		t.Errorf("rustSymCrate(user) = %q, want myapp", got)
	}
	for _, s := range []string{
		"std::io::stdio::print",
		"core::ptr::drop_in_place<T>",
		"__rustc::rust_panic",
		"<myapp::S as core::fmt::Debug>::fmt",
	} {
		if got := rustSymCrate(s); got != "" {
			t.Errorf("rustSymCrate(%q) = %q, want no crate", s, got)
		}
	}
}

func TestRustSymScan(t *testing.T) {
	names := []string{
		"_ZN5myapp3run17h0123456789abcdefE",
		"_ZN4core3ptr107drop_in_place$LT$core..pin..Pin$LT$alloc..boxed..Box$LT$std..sys..pal..unix..sync..mutex..Mutex$GT$$GT$$GT$17hb95559412fbb8a0aE",
		"_RNvCsiGVaDesi5rv_7___rustc10rust_panic",
		"_ZN14rustc_demangle2v07Printer10print_type28_$u7b$$u7b$closure$u7d$$u7d$17h7931f6e232bd6a6fE",
		"_ZN3foo3barE", // C++ shape, no Rust hash: not a Rust name
		"memcpy",
	}
	st := rustSymScan(names)
	if st.total != 4 || st.legacy != 3 || st.v0 != 1 {
		t.Fatalf("total/legacy/v0 = %d/%d/%d, want 4/3/1", st.total, st.legacy, st.v0)
	}
	if st.glue != 1 || st.panic != 1 || st.closure != 1 {
		t.Fatalf("glue/panic/closure = %d/%d/%d, want 1/1/1", st.glue, st.panic, st.closure)
	}
	if len(st.crates) != 1 || st.crates[0] != "myapp" {
		t.Fatalf("crates = %v, want [myapp]", st.crates)
	}
	if len(st.samples) != 1 || st.samples[0] != "myapp::run" {
		t.Fatalf("samples = %v, want [myapp::run]", st.samples)
	}
}

func TestRustSymScanFindsMainCrate(t *testing.T) {
	st := rustSymScan([]string{
		"_ZN5myapp3run17h0123456789abcdefE",
		"_ZN1r4main17h0123456789abcdefE",
	})
	if st.mainCrate != "r" {
		t.Fatalf("mainCrate = %q, want r", st.mainCrate)
	}
	st = rustSymScan([]string{"_ZN5myapp3run17h0123456789abcdefE"})
	if st.mainCrate != "" {
		t.Fatalf("mainCrate = %q, want empty without a main function", st.mainCrate)
	}
}

func TestRustSymNotesStayBounded(t *testing.T) {
	long := "crate::module::" + strings.Repeat("very_long_generic_argument", 20)
	if got := rustClip(long, rustSymNoteCap); len(got) > rustSymNoteCap || !strings.HasSuffix(got, "...") {
		t.Fatalf("rustClip(len %d) = %q, want clipped at %d", len(long), got, rustSymNoteCap)
	}
	if got := rustClip("short", rustSymNoteCap); got != "short" {
		t.Fatalf("rustClip(short) = %q", got)
	}
}

func TestInspectRustSymIgnoresNonNativeKinds(t *testing.T) {
	d := &Digest{Kind: "zip"}
	inspectRustSym("does-not-exist", d) // must return before opening anything
	if len(d.Notes) != 0 || len(d.Skipped) != 0 || len(d.Capabilities) != 0 {
		t.Fatalf("non-native digest mutated: %+v", d)
	}
}
