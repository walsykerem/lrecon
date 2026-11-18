package main

// final.md 51: current_address.
func init() {
	registerOp(op{
		name:  "current_address",
		route: "L",
		desc:  "the cursor recorded by goto_address, resolved against the session document's function table",
		needs: false,
		run: func(path string) (any, error) {
			s, err := sessionFor("")
			if err != nil {
				return nil, err
			}
			out := map[string]any{
				"project":   s.Project,
				"document":  s.Document,
				"address":   nativeHexAddr(s.Cursor),
				"procedure": s.Procedure,
			}
			fns, ferr := nativeFunctions(s.Document)
			if ferr != nil {
				out["functions"] = 0
				out["note"] = "session document has no function table: " + ferr.Error()
				return out, nil
			}
			out["functions"] = len(fns)
			if f := containingFunction(fns, s.Cursor); f != nil {
				out["procedure"] = f.Name
				out["procedure_entry"] = nativeHexAddr(f.Start)
				out["offset_in_function"] = s.Cursor - f.Start
			}
			return out, nil
		},
	})
}
