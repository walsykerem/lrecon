package main

// final: inspect_android_package.
func init() {
	registerOp(op{
		name:  "inspect_android_package",
		route: "L",
		needs: true,
		desc:  "Android package (apk/aab): package id, min/target sdk, requested permissions and detected capabilities from the digest",
		run: func(path string) (any, error) {
			d, err := Probe(path)
			if err != nil {
				return nil, err
			}
			if d.Kind != "apk" && d.Kind != "aab" {
				return skipf("%s: %s, not an Android package (apk/aab)", path, d.Kind), nil
			}
			return struct {
				Kind         string   `json:"kind"`
				Package      string   `json:"package"`
				SDK          string   `json:"sdk"`
				Permissions  []string `json:"permissions"`
				Capabilities []string `json:"capabilities"`
				Notes        []string `json:"notes,omitempty"`
			}{d.Kind, d.MobilePkg, d.MobileSDK, d.MobilePerms, d.Capabilities, d.Notes}, nil
		},
	})
}
