package main

// Digest field contract (final.md 106): what an absent value means.
//
// String fields are plain Go strings, so the JSON always carries a string:
//
//	""   the field does not apply to this target, or the target does not carry
//	     it. A fat Mach-O has no single minos/uuid (they live per slice in
//	     slice_info); an asar has no format; a target without LC_SONAME has no
//	     soname. An empty string never means "not scanned" — that is what
//	     constants/coverage/truncated are for.
//
// Collections carry the difference between "not measured" and "measured none":
//
//	null  the collection was never populated: no reader ran, the reader was
//	      cut before it could answer, or the question does not apply.
//	[]    the question was answered and the answer is none (a probe that
//	      scanned for rpaths/imports/capabilities and found zero).
//
// The zero Digest marshals string fields as "" and nil slices as null; a
// reader that fills an empty list must use a non-nil empty slice. This is the
// whole contract; no presence booleans are needed because the kind decides
// which strings can apply.
