package main

import (
	"archive/zip"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"strings"
)

// apkSigBlockID is the APK Signing Block footer magic.
const apkSigBlockID = "APK Sig Block 42"

var apkSchemeIDs = map[uint32]string{
	0x7109871a: "v2",
	0xf05368c0: "v3",
	0x1b93ad61: "v3.1",
	0x42726577: "verity-padding",
}

func init() {
	registerOp(op{
		name:  "inspect_apk_signature",
		route: "L",
		needs: true,
		desc:  "APK v1 PKCS#7 signers plus v2/v3 ID-value pairs from the APK Signing Block",
		run: func(path string) (any, error) {
			b, err := opRead(path, opMaxFile)
			if err != nil {
				return nil, err
			}
			type signer struct {
				Source  string `json:"source"`
				Subject string `json:"subject,omitempty"`
				SHA256  string `json:"sha256,omitempty"`
			}
			res := struct {
				Signed   bool     `json:"signed"`
				Schemes  []string `json:"schemes"`
				Signers  []signer `json:"signers,omitempty"`
				BlockLen int      `json:"signing_block_bytes,omitempty"`
				Pairs    []string `json:"pairs,omitempty"`
			}{}
			if zr, zerr := zip.OpenReader(path); zerr == nil {
				for _, f := range zr.File {
					up := strings.ToUpper(f.Name)
					if !strings.HasPrefix(up, "META-INF/") || !strings.HasSuffix(up, ".RSA") &&
						!strings.HasSuffix(up, ".DSA") && !strings.HasSuffix(up, ".EC") {
						continue
					}
					raw, ok := readEntry(f, 8<<20)
					if !ok {
						continue
					}
					for _, c := range pkcs7Certs(raw) {
						sum := sha256.Sum256(c.Raw)
						res.Signers = append(res.Signers, signer{Source: "v1 " + f.Name, Subject: c.Subject.String(),
							SHA256: hex.EncodeToString(sum[:])})
					}
					if len(res.Schemes) == 0 {
						res.Schemes = append(res.Schemes, "v1")
					}
				}
				zr.Close()
			}
			// Gate on ZIP structure before scanning: zip.OpenReader error
			// ignored above would let non-ZIP targets fall through to
			// ok. EOCD search finds no central directory -> the target
			// is not an APK; bad_arg, not Signed:false.
			if !bytesHasEOCD(b) {
				return nil, fmt.Errorf("%s is not a zip/apk archive (no end-of-central-directory record)", path)
			}
			pairs, blockLen, perr := apkSigningBlock(b)
			if perr != nil {
				res.Schemes = []string{}
				res.Signed = false
				return res, nil
			}
			res.BlockLen = blockLen
			for _, id := range pairs {
				name, ok := apkSchemeIDs[id]
				if !ok {
					name = fmt.Sprintf("%#08x", id)
				}
				res.Pairs = append(res.Pairs, name)
				if _, known := apkSchemeIDs[id]; known && name != "verity-padding" {
					res.Schemes = append(res.Schemes, name)
				}
			}
			if len(res.Schemes) == 0 {
				res.Schemes = []string{}
				res.Signed = false
				res.Signers = []signer{}
				return res, nil
			}
			res.Schemes = uniqSorted(res.Schemes)
			res.Signed = true
			return res, nil
		},
	})
}

// bytesHasEOCD reports whether b holds a ZIP end-of-central-directory record
// in its trailing window — the smallest gate for "is this a zip/apk at all".
func bytesHasEOCD(b []byte) bool {
	for i := len(b) - 22; i >= 0 && i > len(b)-65558; i-- {
		if u32le(b, i) == 0x06054b50 {
			return true
		}
	}
	return false
}

// apkSigningBlock locates the block that sits immediately before the ZIP central
// directory and returns the IDs of its ID-value pairs.
func apkSigningBlock(b []byte) ([]uint32, int, error) {
	eocd := -1
	for i := len(b) - 22; i >= 0 && i > len(b)-65558; i-- {
		if u32le(b, i) == 0x06054b50 {
			eocd = i
			break
		}
	}
	if eocd < 0 {
		return nil, 0, fmt.Errorf("no end-of-central-directory record")
	}
	cdOff := int(u32le(b, eocd+16))
	if cdOff < 32 || cdOff > len(b) {
		return nil, 0, fmt.Errorf("central directory offset %#x is out of range", cdOff)
	}
	if string(b[cdOff-16:cdOff]) != apkSigBlockID {
		return nil, 0, fmt.Errorf("no APK Signing Block before the central directory")
	}
	size := int(u64le(b, cdOff-24))
	start := cdOff - size - 8
	if size < 32 || start < 0 || start+8 > len(b) {
		return nil, 0, fmt.Errorf("signing block size %#x is out of range", size)
	}
	if got := int(u64le(b, start)); got != size {
		return nil, 0, fmt.Errorf("signing block header size %#x disagrees with footer %#x", got, size)
	}
	var ids []uint32
	for off := start + 8; off+12 <= cdOff-24; {
		n := int(u64le(b, off))
		if n < 4 || off+8+n > len(b) {
			break
		}
		ids = append(ids, u32le(b, off+8))
		off += 8 + n
	}
	return ids, size + 8, nil
}

// pkcs7Certs pulls the certificates out of a DER PKCS#7 SignedData blob.
func pkcs7Certs(raw []byte) []*x509.Certificate {
	type contentInfo struct {
		Type asn1.ObjectIdentifier
		Body asn1.RawValue `asn1:"explicit,tag:0"`
	}
	var ci contentInfo
	if _, err := asn1.Unmarshal(raw, &ci); err != nil {
		return nil
	}
	type signedData struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		Content          asn1.RawValue
		Certificates     asn1.RawValue `asn1:"optional,tag:0"`
		SignerInfos      asn1.RawValue
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Body.Bytes, &sd); err != nil {
		return nil
	}
	var out []*x509.Certificate
	rest := sd.Certificates.Bytes
	for len(rest) > 0 {
		var rv asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &rv)
		if err != nil {
			break
		}
		c, cerr := x509.ParseCertificate(rv.FullBytes)
		if cerr != nil {
			continue
		}
		out = append(out, c)
	}
	return out
}
