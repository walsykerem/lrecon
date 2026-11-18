package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// consts is a hit list that renders as a plain string when it only carries a
// sentinel, so a consumer can test constants == "not_detected" without knowing
// it is stored as a list. Unmarshal accepts both forms for --diff round trips.
type consts []string

func (c consts) MarshalJSON() ([]byte, error) {
	if len(c) == 1 && (c[0] == constNotDetected || c[0] == constNotScanned) {
		return json.Marshal(c[0])
	}
	return json.Marshal([]string(c))
}

func (c *consts) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*c = consts{s}
		return nil
	}
	var l []string
	if err := json.Unmarshal(b, &l); err != nil {
		return err
	}
	*c = l
	return nil
}

type Dep struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

// contractVersion freezes the JSON key set. Every key below is always emitted,
// so a consumer can rely on the shape; bump this when a key changes meaning or
// disappears, and --diff refuses a saved digest it would misread.
const contractVersion = 1

// Target is the byte identity of what a digest describes. HashScope says which
// bytes were hashed: "whole-file" for a regular file, "none" for a directory
// (a bundle has no single byte stream). GitOID is the git blob id, sha1 over
// "blob <n>\0" followed by the file bytes.
type Target struct {
	Size       int64  `json:"size"`
	FileSHA256 string `json:"file_sha256"`
	HashScope  string `json:"hash_scope"`
	HashBytes  int64  `json:"hash_bytes"`
	GitOID     string `json:"gitoid"`
}

// Digest is the single output contract: everything lrecon learns about a target.
// Keep field names stable, tests and the skill both read them.
type Digest struct {
	ContractVersion int        `json:"contract_version"`
	Target          Target     `json:"target"`
	Path            string     `json:"-"` // local path, not part of the contract
	Kind            string     `json:"kind"`
	Format          string     `json:"format"`
	Slices          int        `json:"slices"`
	Toolchain       string     `json:"toolchain"`
	Mod             string     `json:"mod"`
	Deps            []Dep      `json:"deps"`
	Dylibs          []string   `json:"dylibs"`
	Imports         []string   `json:"imports"`
	Capabilities    []string   `json:"capabilities"`
	AsarFiles       int        `json:"asar_files"`
	AsarMain        string     `json:"asar_main"`
	AsarProduct     string     `json:"asar_product"`
	AsarVersion     string     `json:"asar_version"`
	ElectronVer     string     `json:"electron"`
	UnpackedNode    int        `json:"asar_unpacked_native"`
	FlutterHash     string     `json:"flutter_hash"`
	Notes           []string   `json:"-"` // internal claims; JSON carries Plan instead
	Plan            string     `json:"plan"`
	Hardening       []string   `json:"hardening"` // nx, pie, aslr, dep, cfg, canary, fortify, relro-full/relro-partial, codesign, debug-info:*
	MinOS           string     `json:"minos"`
	UUID            string     `json:"uuid"`
	Rpaths          []string   `json:"rpaths"`
	Exports         int        `json:"exports"`
	Symbols         string     `json:"symbols"`    // present|stripped: whether a symbol table existed at all
	Entrypoint      *uint64    `json:"entrypoint"` // e_entry / LC_MAIN / AddressOfEntryPoint; null when the target declares none
	Constants       consts     `json:"constants"`  // label|strength|segment,section|0xoffset, or not_detected
	JIT             string     `json:"jit"`        // not_detected | imports:<tokens>
	Names           string     `json:"names"`      // local:<count> | pclntab:<count> | not_recovered
	SliceInfo       []string   `json:"slice_info"` // one line per fat slice: arch, minos, uuid, exports, hardening
	Soname          string     `json:"soname"`
	BuildID         string     `json:"build_id"`
	Subsystem       string     `json:"subsystem"`
	PDB             string     `json:"pdb"`
	Extracted       string     `json:"extracted"` // path written by --extract
	PcapPackets     int        `json:"pcap_packets"`
	PcapLinkType    string     `json:"pcap_link_type"`
	PcapSpan        string     `json:"pcap_span"`
	PcapProtos      []string   `json:"pcap_protocols"`
	PcapDNS         []string   `json:"pcap_dns"`
	PcapSNI         []string   `json:"pcap_sni"`
	PcapURIs        []string   `json:"pcap_uris"`
	FirmwareEnd     int        `json:"firmware_parts"`
	FirmwareParts   []string   `json:"firmware_detail"` // was firmware_parts_format: collided with the count key
	FirmwareKind    string     `json:"firmware_kind"`
	MobilePkg       string     `json:"mobile_package"`
	MobilePerms     []string   `json:"mobile_permissions"`
	MobileSDK       string     `json:"mobile_sdk"`
	SQLitePageSize  int        `json:"sqlite_page_size"`
	SQLiteVersion   string     `json:"sqlite_version"`
	SQLiteWAL       bool       `json:"sqlite_wal"`
	ElectronIPC     []string   `json:"electron_ipc"`
	SourceMaps      []string   `json:"source_map"`
	RustCrates      []string   `json:"rust_crate"`
	PlistKeys       []string   `json:"plist_key"`
	Skeleton        *Skeleton  `json:"skeleton"`
	Coverage        *Coverage  `json:"coverage"`
	Skipped         []Skip     `json:"skipped"`
	Claims          []Claim    `json:"claims"`
	Unknown         []Unknown  `json:"unknown"`
	Conflicts       []Conflict `json:"conflicts"`
	BytesScanned    int64      `json:"bytes_scanned"`
	FileSize        int64      `json:"file_size"`
	Truncated       bool       `json:"truncated"`
	reasonErrs      []string   // refusal detail, never part of the JSON contract
	witnesses       []Witness  // byte ranges readers actually saw, written by d.witness
}

// textFieldCap bounds one target-derived field: a hostile string must not crowd
// the whole 4096-byte budget, and a cut field is reported, not hidden.
const textFieldCap = 256

// textSafe makes a target-derived string safe to print on one line. A pcap URI
// carrying "\x1b[2K\rforged: x" must not reach a reader as a second line, so
// control bytes are dropped and CR/LF/TAB are escaped. Dropped and capped bytes
// are counted so "absent" and "trimmed" stay distinguishable.
func textSafe(s string) (string, int) {
	var sb strings.Builder
	omitted := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\r':
			sb.WriteString(`\r`)
		case c == '\n':
			sb.WriteString(`\n`)
		case c == '\t':
			sb.WriteString(`\t`)
		case c < 0x20 || c == 0x7f:
			omitted++
		case sb.Len() >= textFieldCap:
			omitted++
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String(), omitted
}

// textLine appends one sanitized "key: value" line, naming what it removed.
func textLine(b *strings.Builder, prefix, s string) {
	v, n := textSafe(s)
	if n > 0 {
		v += fmt.Sprintf(" omitted:%d", n)
	}
	fmt.Fprintf(b, "%s%s\n", prefix, v)
}

// Text renders the fixed-budget digest an agent reads instead of 400 lines of strings.
func (d Digest) Text() string {
	var b strings.Builder
	line := func(k, v string) {
		if v != "" {
			textLine(&b, k+": ", v)
		}
	}
	ind := func(s string) { textLine(&b, "  ", s) }
	line("kind", d.Kind)
	line("format", d.Format)
	if d.Slices > 0 {
		line("slices", fmt.Sprint(d.Slices))
		for _, s := range d.SliceInfo {
			ind(s)
		}
	}
	line("minos", d.MinOS)
	line("uuid", d.UUID)
	line("soname", d.Soname)
	line("build_id", d.BuildID)
	line("subsystem", d.Subsystem)
	line("pdb", d.PDB)
	// A zero export count is an answer, not an omission: docs decide on it, so it
	// prints whenever a symbol source was actually read.
	if d.Exports > 0 || d.Symbols != "" {
		line("exports", fmt.Sprint(d.Exports))
	}
	line("symbols", d.Symbols)
	if d.Entrypoint != nil {
		line("entrypoint", fmt.Sprintf("0x%x", *d.Entrypoint))
	}
	line("names", d.Names)
	if d.Skeleton != nil {
		ind(d.Skeleton.line())
	}
	// Always printed: a count without its denominator is not a bounded claim,
	// and no reader at all is stated as "of N unknown", never omitted.
	line("coverage", d.coverageClaim())
	for _, s := range d.Skipped {
		line("skipped", strings.TrimSpace(s.Reason+" "+s.Detail))
	}
	for _, c := range d.Claims {
		textLine(&b, "claim: ", fmt.Sprintf("%s (%s @%#x)", c.Value, c.Source, c.ByteOffset))
	}
	if d.BytesScanned > 0 || d.FileSize > 0 {
		v := fmt.Sprintf("%d/%d", d.BytesScanned, d.FileSize)
		if d.BytesScanned != d.FileSize {
			v += " scanned" // a partial read, not the whole file
		}
		line("bytes", v)
	}
	if len(d.Constants) == 1 && (d.Constants[0] == constNotDetected || d.Constants[0] == constNotScanned) {
		line("constants", d.Constants[0])
	} else if len(d.Constants) > 0 {
		line("constants", fmt.Sprint(len(d.Constants)))
		for _, c := range d.Constants {
			ind(c)
		}
	}
	line("jit", d.JIT)
	line("toolchain", d.Toolchain)
	line("mod", d.Mod)
	if len(d.Deps) > 0 {
		line("deps", fmt.Sprint(len(d.Deps)))
		for _, dep := range d.Deps {
			ind(dep.Path + " " + dep.Version)
		}
	}
	if len(d.Dylibs) > 0 {
		line("dylibs", fmt.Sprint(len(d.Dylibs)))
		for _, l := range d.Dylibs {
			ind(l)
		}
	}
	line("hardening", strings.Join(d.Hardening, ", "))
	line("capabilities", strings.Join(d.Capabilities, ", "))
	if len(d.Imports) > 0 {
		line("imports", fmt.Sprint(len(d.Imports)))
		for _, s := range d.Imports {
			ind(s)
		}
	}
	if len(d.Rpaths) > 0 {
		line("rpaths", fmt.Sprint(len(d.Rpaths)))
		for _, r := range d.Rpaths {
			ind(r)
		}
	}
	if d.AsarFiles > 0 {
		line("asar_files", fmt.Sprint(d.AsarFiles))
	}
	line("asar_main", d.AsarMain)
	line("asar_product", d.AsarProduct)
	line("asar_version", d.AsarVersion)
	line("electron", d.ElectronVer)
	if d.UnpackedNode > 0 {
		line("asar_unpacked_native", fmt.Sprint(d.UnpackedNode))
	}
	line("flutter_hash", d.FlutterHash)
	line("extracted", d.Extracted)
	if d.PcapPackets > 0 {
		line("pcap_packets", fmt.Sprint(d.PcapPackets))
		line("pcap_link_type", d.PcapLinkType)
		line("pcap_span", d.PcapSpan)
		for _, p := range d.PcapProtos {
			line("pcap_proto", p)
		}
		for _, host := range d.PcapDNS {
			line("pcap_dns", host)
		}
		for _, sni := range d.PcapSNI {
			line("pcap_sni", sni)
		}
		for _, u := range d.PcapURIs {
			line("pcap_uri", u)
		}
	}
	line("mobile_package", d.MobilePkg)
	line("mobile_sdk", d.MobileSDK)
	for _, perm := range d.MobilePerms {
		line("mobile_permission", perm)
	}
	if d.SQLitePageSize > 0 {
		line("sqlite_page_size", fmt.Sprint(d.SQLitePageSize))
	}
	line("sqlite_version", d.SQLiteVersion)
	if d.SQLiteWAL {
		line("sqlite_wal", "true")
	}
	for _, c := range d.ElectronIPC {
		line("electron_ipc", c)
	}
	for _, m := range d.SourceMaps {
		line("source_map", m)
	}
	for _, c := range d.RustCrates {
		line("rust_crate", c)
	}
	for _, k := range d.PlistKeys {
		line("plist_key", k)
	}
	line("firmware_kind", d.FirmwareKind)
	if d.FirmwareEnd > 0 {
		line("firmware_parts", fmt.Sprint(d.FirmwareEnd))
		for _, p := range d.FirmwareParts {
			ind(p)
		}
	}
	for _, n := range d.Notes {
		line("note", n)
	}
	return b.String()
}
