package main

import "encoding/binary"

// final: identify_flutter_build.
func init() {
	registerOp(op{
		name:  "identify_flutter_build",
		route: "L",
		needs: true,
		desc:  "Flutter build identity: Dart snapshot version hash and snapshot kind, or the Flutter capability of an Android package",
		run: func(path string) (any, error) {
			d, err := Probe(path)
			if err != nil {
				return nil, err
			}
			flutterPkg := d.Kind == "apk" || d.Kind == "aab" || d.Kind == "ipa"
			if d.Kind != "flutter" && !(flutterPkg && containsStr(d.Capabilities, "flutter")) {
				return skipf("%s: %s with no Flutter marker; no Dart snapshot hash or libflutter.so found", path, d.Kind), nil
			}
			snapshot := ""
			if d.Kind == "flutter" {
				if h := head(path, dartHeaderSize); len(h) >= dartHeaderSize {
					if name, ok := dartKinds[binary.LittleEndian.Uint64(h[12:20])]; ok {
						snapshot = name
					}
				}
			}
			return struct {
				Kind         string   `json:"kind"`
				Format       string   `json:"format"`
				FlutterHash  string   `json:"flutter_hash"`
				Snapshot     string   `json:"dart_snapshot_kind,omitempty"`
				Package      string   `json:"package,omitempty"`
				Capabilities []string `json:"capabilities"`
				Notes        []string `json:"notes,omitempty"`
			}{d.Kind, d.Format, d.FlutterHash, snapshot, d.MobilePkg, nz(d.Capabilities), nz(d.Notes)}, nil
		},
	})
}
