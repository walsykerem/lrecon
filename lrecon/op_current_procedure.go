package main

// final.md 53: current_procedure.
func init() {
	registerOp(op{
		name:  "current_procedure",
		route: "L",
		desc:  "the function containing the session cursor, with its range and offset into it",
		needs: false,
		run: func(path string) (any, error) {
			s, err := sessionFor("")
			if err != nil {
				return nil, err
			}
			fns, ferr := nativeFunctions(s.Document)
			out := map[string]any{
				"document":  s.Document,
				"address":   nativeHexAddr(s.Cursor),
				"functions": 0,
				"found":     false,
			}
			// Same degrade as current_address: a document without a readable
			// symbol table still has an address to report.
			if ferr != nil {
				out["note"] = "session document has no function table: " + ferr.Error()
				return out, nil
			}
			out["functions"] = len(fns)
			if f := containingFunction(fns, s.Cursor); f != nil {
				out["found"] = true
				out["procedure"] = f.Name
				out["start"] = nativeHexAddr(f.Start)
				out["end"] = nativeHexAddr(f.End)
				out["offset"] = s.Cursor - f.Start
			}
			return out, nil
		},
	})
}
