package main

import "bytes"

// final: inspect_asset_catalog. BOMStore .car catalogs are parsed block by block
// (see op_asset_catalog.go); the CARV variant is still only chunk framing in
// open_bundle_resources, so it keeps an honest refusal, as do Android packages
// and anything that is not a catalog at all.
func init() {
	registerOp(op{
		name:  "inspect_asset_catalog",
		route: "L",
		needs: true,
		desc:  "parse a BOMStore .car asset catalog: header, named blocks, block magics, key format ids, tree pair counts and rendition bytes; refuses CARV chunks and Android packages",
		run: func(path string) (any, error) {
			b, err := opRead(path, opMaxFile)
			if err != nil {
				return nil, err
			}
			// Probe only recognizes the CARV magic, so the BOMStore header is
			// checked here: every shipped .car starts with it and probes unknown.
			if bytes.HasPrefix(b, []byte("BOMStore")) {
				return assetCatalog(path, b)
			}
			d, err := Probe(path)
			if err != nil {
				return nil, err
			}
			switch d.Kind {
			case "car":
				return skipf("%s: CARV container: asset catalog parsing not implemented for this variant; lrecon reads only the BOMStore block and var tables, not CARV chunk payloads", path), nil
			case "apk", "aab":
				return skipf("%s: %s is an Android package, not an iOS/macOS asset catalog; lrecon does not parse Play asset packs or their asset manifests", path, d.Kind), nil
			}
			return skipf("%s: %s is not an asset catalog; lrecon parses only BOMStore .car catalogs (no CARV payloads, no Android asset packs)", path, d.Kind), nil
		},
	})
}
