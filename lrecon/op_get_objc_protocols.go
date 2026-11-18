package main

func init() {
	registerOp(op{
		name:  "get_objc_protocols",
		route: "L",
		needs: true,
		desc:  "walk __objc_protolist → protocol_t → name and list adopted protocols",
		run: func(path string) (any, error) {
			// protocol_t: isa@0, name@8 (64-bit) / name@4 (32-bit).
			names, unresolved, err := objcNameList(path, "__objc_protolist", []int{8}, false)
			if noSection(err) {
				return skipf("%s has no Objective-C protocol list", path), nil
			}
			if err != nil {
				return nil, err
			}
			if len(names) == 0 {
				return skipf("%s: protocol list carries no resolvable names", path), nil
			}
			return struct {
				Count      int      `json:"count"`
				Protocols  []string `json:"protocols"`
				Unresolved int      `json:"unresolved,omitempty"`
			}{Count: len(names) + unresolved, Protocols: capN(uniqSorted(names), 100), Unresolved: unresolved}, nil
		},
	})
}
