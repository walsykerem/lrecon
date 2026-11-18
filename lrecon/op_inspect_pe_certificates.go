package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"hash"
	"sort"
)

// Data directory 4 points at a WIN_CERTIFICATE table; unlike every other
// directory its rva field is a plain file offset.

var (
	peOIDSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	peOIDMsgDigest  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
)

var peDigestNames = map[string]string{
	"1.2.840.113549.2.5":     "md5",
	"1.3.14.3.2.26":          "sha1",
	"2.16.840.1.101.3.4.2.1": "sha256",
	"2.16.840.1.101.3.4.2.2": "sha384",
	"2.16.840.1.101.3.4.2.3": "sha512",
}

var peCertRevisionNames = map[uint16]string{0x0100: "1.0", 0x0200: "2.0"}

var peCertTypeNames = map[uint16]string{1: "x509", 2: "pkcs7", 3: "reserved", 4: "ts-stack"}

type peCertX509 struct {
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
	Serial    string `json:"serial"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	SHA256    string `json:"sha256"`
}

type peCertSigner struct {
	DigestAlgorithm    string `json:"digest_algorithm"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	MessageDigest      string `json:"message_digest,omitempty"`
}

type peCertEntry struct {
	Length       uint32         `json:"length"`
	Revision     uint16         `json:"revision"`
	RevisionName string         `json:"revision_name"`
	Type         uint16         `json:"type"`
	TypeName     string         `json:"type_name"`
	SHA256       string         `json:"sha256"`
	ImageDigest  string         `json:"image_digest,omitempty"`
	Certificates []peCertX509   `json:"certificates,omitempty"`
	Signers      []peCertSigner `json:"signers,omitempty"`
}

type peAlgID struct {
	Algorithm asn1.ObjectIdentifier
	Params    asn1.RawValue `asn1:"optional"`
}

type peSignerInfoT struct {
	Version            int
	IssuerAndSerial    asn1.RawValue
	DigestAlgorithm    peAlgID
	AuthAttrs          asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm peAlgID
	Signature          []byte
}

type peSignedDataT struct {
	Version          int
	DigestAlgorithms []peAlgID `asn1:"set"`
	ContentInfo      asn1.RawValue
	Certificates     asn1.RawValue   `asn1:"optional,tag:0"`
	SignerInfos      []peSignerInfoT `asn1:"set"`
}

type peContentInfoT struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

func peParseSigners(raw []byte) ([]peCertSigner, error) {
	var ci peContentInfoT
	if _, err := asn1.Unmarshal(raw, &ci); err != nil {
		return nil, fmt.Errorf("PKCS#7 ContentInfo: %v", err)
	}
	if !ci.ContentType.Equal(peOIDSignedData) {
		return nil, fmt.Errorf("PKCS#7 content type is %s, not SignedData", ci.ContentType)
	}
	var sd peSignedDataT
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("PKCS#7 SignedData: %v", err)
	}
	out := make([]peCertSigner, 0, len(sd.SignerInfos))
	for i, si := range sd.SignerInfos {
		s := peCertSigner{
			DigestAlgorithm:    peDigestName(si.DigestAlgorithm.Algorithm),
			SignatureAlgorithm: si.SignatureAlgorithm.Algorithm.String(),
		}
		if d, ok := peMsgDigest(si.AuthAttrs); ok {
			s.MessageDigest = hex.EncodeToString(d)
		} else if len(si.AuthAttrs.Bytes) != 0 {
			return nil, fmt.Errorf("PKCS#7 signer %d: authenticated attributes carry no messageDigest", i)
		}
		out = append(out, s)
	}
	return out, nil
}

func peDigestName(oid asn1.ObjectIdentifier) string {
	if n, ok := peDigestNames[oid.String()]; ok {
		return n
	}
	return oid.String()
}

// peMsgDigest pulls the single OCTET STRING out of the messageDigest attribute.
// authenticatedAttributes is a [0] IMPLICIT SET, so its contents are the
// attribute sequences directly; a few encoders add the SET tag anyway.
func peMsgDigest(attrs asn1.RawValue) ([]byte, bool) {
	if len(attrs.Bytes) == 0 {
		return nil, false
	}
	rest := attrs.Bytes
	for len(rest) > 0 {
		if rest[0] == 0x31 {
			var set asn1.RawValue
			if _, err := asn1.Unmarshal(rest, &set); err != nil {
				return nil, false
			}
			rest = set.Bytes
			continue
		}
		var attr struct {
			Type   asn1.ObjectIdentifier
			Values asn1.RawValue `asn1:"set"`
		}
		var err error
		rest, err = asn1.Unmarshal(rest, &attr)
		if err != nil {
			return nil, false
		}
		if !attr.Type.Equal(peOIDMsgDigest) {
			continue
		}
		var oct asn1.RawValue
		if _, err := asn1.Unmarshal(attr.Values.Bytes, &oct); err != nil || oct.Tag != 0x04 {
			return nil, false
		}
		return oct.Bytes, true
	}
	return nil, false
}

// peImageHash is the Authenticode digest: the headers without the checksum and
// the security directory entry, then every section except the certificate
// table, in file order.
func peImageHash(p *peFile, alg string, certOff, certSize uint32) ([]byte, error) {
	var h hash.Hash
	switch alg {
	case "sha1":
		h = sha1.New()
	case "sha256":
		h = sha256.New()
	case "sha384":
		h = sha512.New384()
	case "sha512":
		h = sha512.New()
	default:
		return nil, fmt.Errorf("unsupported digest %s", alg)
	}
	checksum := p.optOff + 64
	secDir := p.dirOff + 4*8
	head := p.sizeOfHeaders
	if head == 0 || int(head) > len(p.b) {
		head = uint32(len(p.b))
	}
	for _, r := range [][2]uint32{{0, uint32(checksum)}, {uint32(checksum + 4), uint32(secDir)}, {uint32(secDir + 8), head}} {
		if r[0] < r[1] && int(r[1]) <= len(p.b) {
			h.Write(p.b[r[0]:r[1]])
		}
	}
	sects := append([]peSec(nil), p.sects...)
	sort.Slice(sects, func(i, j int) bool { return sects[i].off < sects[j].off })
	for _, s := range sects {
		if s.rawSize == 0 {
			continue
		}
		start, end := int(s.off), int(s.off)+int(s.rawSize)
		if start >= len(p.b) {
			continue
		}
		if end > len(p.b) {
			end = len(p.b)
		}
		if certSize != 0 && start < int(certOff+certSize) && end > int(certOff) {
			// The certificate table lives inside a section's raw data; skip
			// exactly its bytes and hash the rest of the section.
			if start < int(certOff) {
				h.Write(p.b[start:certOff])
			}
			if tail := int(certOff + certSize); tail < end {
				h.Write(p.b[tail:end])
			}
			continue
		}
		h.Write(p.b[start:end])
	}
	return h.Sum(nil), nil
}

func init() {
	registerOp(op{
		name:  "inspect_pe_certificates",
		route: "L",
		needs: true,
		desc:  "PE certificate table: WIN_CERTIFICATE records, PKCS#7 signer/certificate fields and the Authenticode image digest recomputed from the file",
		run: func(path string) (any, error) {
			b, err := opRead(path, opMaxFile)
			if err != nil {
				return nil, err
			}
			p, err := openPEBytes(b)
			if err != nil {
				return nil, fmt.Errorf("%s: %v", path, err)
			}
			certOff, certSize, err := p.dir(peDirSecurity)
			if err != nil {
				return nil, fmt.Errorf("%s: %v", path, err)
			}
			if certOff == 0 || certSize == 0 {
				return struct {
					Present bool          `json:"present"`
					Signed  bool          `json:"signed"`
					Offset  uint64        `json:"offset"`
					Size    uint32        `json:"size"`
					Entries []peCertEntry `json:"entries"`
				}{false, false, 0, 0, []peCertEntry{}}, nil
			}
			if uint64(certOff)+uint64(certSize) > uint64(len(b)) {
				return nil, fmt.Errorf("%s certificate table %#x+%d runs past the file", path, certOff, certSize)
			}
			table := b[certOff : certOff+certSize]
			out := struct {
				Present bool          `json:"present"`
				Signed  bool          `json:"signed"`
				Offset  uint64        `json:"offset"`
				Size    uint32        `json:"size"`
				Entries []peCertEntry `json:"entries"`
			}{true, true, uint64(certOff), certSize, []peCertEntry{}}
			for off := 0; off < len(table); {
				if off+8 > len(table) {
					return nil, fmt.Errorf("%s WIN_CERTIFICATE header at table+%#x is cut", path, off)
				}
				length := u32le(table, off)
				if length < 8 || uint64(off)+uint64(length) > uint64(len(table)) {
					return nil, fmt.Errorf("%s WIN_CERTIFICATE at table+%#x declares %d bytes, table holds %d", path, off, length, len(table)-off)
				}
				rev, typ := u16le(table, off+4), u16le(table, off+6)
				body := table[off+8 : off+int(length)]
				sum := sha256.Sum256(body)
				e := peCertEntry{
					Length: length, Revision: rev, RevisionName: peCertRevisionNames[rev],
					Type: typ, TypeName: peCertTypeNames[typ], SHA256: hex.EncodeToString(sum[:]),
				}
				if e.RevisionName == "" {
					e.RevisionName = fmt.Sprintf("0x%04x", rev)
				}
				if e.TypeName == "" {
					e.TypeName = fmt.Sprintf("0x%04x", typ)
				}
				if typ == 0x0002 {
					for _, c := range pkcs7Certs(body) {
						cs := sha256.Sum256(c.Raw)
						e.Certificates = append(e.Certificates, peCertX509{
							Subject: c.Subject.String(), Issuer: c.Issuer.String(),
							Serial: c.SerialNumber.Text(16), NotBefore: c.NotBefore.UTC().Format("2006-01-02"),
							NotAfter: c.NotAfter.UTC().Format("2006-01-02"), SHA256: hex.EncodeToString(cs[:]),
						})
					}
					signers, err := peParseSigners(body)
					if err != nil {
						return nil, fmt.Errorf("%s WIN_CERTIFICATE at table+%#x: %v", path, off, err)
					}
					e.Signers = signers
					e.ImageDigest, err = peVerifyDigest(p, signers, certOff, certSize)
					if err != nil {
						return nil, fmt.Errorf("%s WIN_CERTIFICATE at table+%#x: %v", path, off, err)
					}
				}
				out.Entries = append(out.Entries, e)
				off += int((length + 7) &^ 7)
			}
			if len(out.Entries) == 0 {
				return nil, fmt.Errorf("%s certificate table holds no WIN_CERTIFICATE record", path)
			}
			return out, nil
		},
	})
}

func peVerifyDigest(p *peFile, signers []peCertSigner, certOff, certSize uint32) (string, error) {
	var s *peCertSigner
	for i := range signers {
		if signers[i].MessageDigest != "" {
			s = &signers[i]
			break
		}
	}
	if s == nil {
		if len(signers) == 0 {
			return "no signer", nil
		}
		return "signer has no messageDigest attribute", nil
	}
	want, err := hex.DecodeString(s.MessageDigest)
	if err != nil {
		return "", fmt.Errorf("messageDigest %q is not hex", s.MessageDigest)
	}
	got, err := peImageHash(p, s.DigestAlgorithm, certOff, certSize)
	if err != nil {
		return "unsupported digest " + s.DigestAlgorithm, nil
	}
	if len(got) == len(want) && string(got) == string(want) {
		return "match", nil
	}
	return "mismatch: image is " + hex.EncodeToString(got), nil
}
