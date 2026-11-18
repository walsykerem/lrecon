package main

import "strings"

// final: inspect_desktop_application.
func init() {
	registerOp(op{
		name:  "inspect_desktop_application",
		route: "L",
		needs: true,
		desc:  "desktop app bundle or Electron asar: bundle kind/format, asar identity, Electron version, unpacked native count and IPC channels",
		run: func(path string) (any, error) {
			d, err := Probe(path)
			if err != nil {
				return nil, err
			}
			// A .app bundle keeps the kind of the artifact it wraps, so the
			// bundle itself is only named in the digest notes.
			bundle := false
			for _, n := range d.Notes {
				if strings.HasPrefix(n, "app bundle: ") {
					bundle = true
					break
				}
			}
			if d.Kind != "app" && d.Kind != "asar" && d.Format != "electron" && !bundle {
				return skipf("%s: %s, not a desktop app bundle or Electron asar", path, d.Kind), nil
			}
			return struct {
				Kind         string   `json:"kind"`
				Format       string   `json:"format"`
				Electron     string   `json:"electron,omitempty"`
				AsarFiles    int      `json:"asar_files,omitempty"`
				AsarMain     string   `json:"asar_main,omitempty"`
				AsarProduct  string   `json:"asar_product,omitempty"`
				AsarVersion  string   `json:"asar_version,omitempty"`
				UnpackedNode int      `json:"asar_unpacked_native,omitempty"`
				ElectronIPC  []string `json:"electron_ipc,omitempty"`
				Capabilities []string `json:"capabilities"`
				Notes        []string `json:"notes,omitempty"`
			}{d.Kind, d.Format, d.ElectronVer, d.AsarFiles, d.AsarMain, d.AsarProduct,
				d.AsarVersion, d.UnpackedNode, d.ElectronIPC, nz(d.Capabilities), d.Notes}, nil
		},
	})
}
