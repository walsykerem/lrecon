package main

// final.md 60: goto_address.
func init() {
	registerOp(op{
		name:  "goto_address",
		route: "L",
		desc:  "validate LRECON_AT inside a file-backed section of the target and make it the session cursor",
		needs: true,
		run: func(path string) (any, error) {
			at, err := nativeAddrArg()
			if err != nil {
				return nil, err
			}
			abs, err := absTarget(path)
			if err != nil {
				return nil, err
			}
			sec, mapping, err := requireInSection(abs, at)
			if err != nil {
				return nil, err
			}
			s, err := loadOrInitSession()
			if err != nil {
				return nil, err
			}
			s = selectDocument(s, abs)
			s.Cursor = at
			s.Procedure = ""
			if fns, ferr := nativeFunctions(abs); ferr == nil {
				if f := containingFunction(fns, at); f != nil {
					s.Procedure = f.Name
				}
			}
			if err := saveSession(s); err != nil {
				return nil, err
			}
			return map[string]any{
				"project":         s.Project,
				"document":        abs,
				"address":         nativeHexAddr(s.Cursor),
				"procedure":       s.Procedure,
				"section":         sec.Name,
				"section_address": nativeHexAddr(sec.Addr),
				"mapping":         mapping,
				"session":         sessionPath(),
			}, nil
		},
	})
}
