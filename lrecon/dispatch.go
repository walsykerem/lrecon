package main

// A reader owns one format and registers itself from its own init(), so adding
// a format never edits the detector and two readers never touch one file.
//
// Two kinds:
//
//	magic readers claim a file by its first bytes (match != nil, post == false)
//	post readers run after the magic switch for formats with no magic of their
//	own (Swift metadata is dispatched on section names, so Mach-O owns the file)
type reader struct {
	format  string
	reasons []string // closed set of skip reasons this reader may emit
	match   func(head []byte, size int64) bool
	inspect func(path string, d *Digest)
	post    bool
	// claimsKind lets a post reader name the file when nothing else did. It never
	// overrides a real magic kind (php-opcache, phar): a bundle inside a Mach-O
	// stays macho and says so in capabilities.
	claimsKind bool
}

var readers []reader

// readersVerified remembers that the register contract was checked for the
// current reader table. The check walks every reader and a digest runs it
// twice (dispatch and dispatchPost), so the table is checked once and a later
// registration asks for the check again.
var readersVerified bool

func register(r reader) {
	if r.format == "" || r.inspect == nil {
		panic("register: reader without format or inspect: " + r.format)
	}
	if len(r.reasons) == 0 {
		panic(`register: reader "` + r.format + `" registered with no reasons`)
	}
	// A reader's own init may fill its set after registering (java does), so the
	// final check runs at dispatch, when every init has run. A set that is already
	// present still refuses an outside literal at register time.
	if set := reasonRegistry[r.format]; set != nil {
		for _, reason := range r.reasons {
			if !set[reason] {
				panic("register: reader " + r.format + " declares reason " + reason + " outside its set")
			}
		}
	}
	if !r.post && r.match == nil {
		panic("register: magic reader without match: " + r.format)
	}
	for _, have := range readers {
		if have.format == r.format {
			panic("register: duplicate reader: " + r.format)
		}
	}
	readers = append(readers, r)
	readersVerified = false
}

// dispatch runs the first magic reader that matches and reports whether the
// file was claimed. Order is registration order, which init() keeps stable
// per file but not across files: match rules must not overlap.
func dispatch(path string, head []byte, size int64, d *Digest) bool {
	verifyReaders()
	for _, r := range readers {
		if r.post || !r.match(head, size) {
			continue
		}
		claim(r, path, d)
		return true
	}
	return false
}

// dispatchPost gives section-name and trailer formats a turn on files another
// reader already claimed. It never changes d.Kind. A post reader may still set
// match as a cheap prefilter on the head bytes.
func dispatchPost(path string, head []byte, size int64, d *Digest) {
	verifyReaders()
	for _, r := range readers {
		if !r.post || (r.match != nil && !r.match(head, size)) {
			continue
		}
		claim(r, path, d)
	}
}

// verifyReaders enforces the per-format half of the register contract: every
// reader names a set, every declared reason belongs to it. It runs on dispatch
// because a reader's init may fill its registry entry after register() returns.
func verifyReaders() {
	if readersVerified {
		return
	}
	for _, r := range readers {
		set := reasonRegistry[r.format]
		if set == nil {
			panic("register: reader " + r.format + " has no reason set")
		}
		for _, reason := range r.reasons {
			if !set[reason] {
				panic("register: reader " + r.format + " declares reason " + reason + " outside its set")
			}
		}
	}
	readersVerified = true
}

func claim(r reader, path string, d *Digest) {
	if !r.post || (r.claimsKind && (d.Kind == "unknown" || d.Kind == "text")) {
		d.Kind = r.format
		if d.Format == "" {
			d.Format = r.format
		}
	}
	setActiveReasons(activeReasonsFor(r.format, r.reasons))
	r.inspect(path, d)
	clearActiveReasons()
	// A reader that could not attribute any unit never proved its format:
	// unparsed counts coverage.Unknown, and claims/parsed never fired.
	// Claiming the format anyway would fabricate a kind from one magic
	// probe. Revert only when the reader never stamped a toolchain or a
	// note about the unit it tried to read: java module-info and invalid
	// constant-pool cases set Toolchain before refusing, and they are
	// correctly-attributed refusals (kind must stay "java"), not junk.
	toolchainBefore := d.Toolchain
	if d.Coverage != nil && d.Coverage.Parsed == 0 && d.Coverage.Unknown > 0 &&
		!r.post && len(d.Claims) == 0 && d.Format == r.format && toolchainBefore == "" {
		d.Kind = "unknown"
		d.Format = ""
	}
}
