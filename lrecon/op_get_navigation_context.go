package main

// final.md 59: get_navigation_context.
func init() {
	registerOp(op{
		name:  "get_navigation_context",
		route: "L",
		desc:  "one call with the session document, cursor, containing procedure and project",
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
				"documents": s.Documents,
				"session":   sessionPath(),
			}
			fns, ferr := nativeFunctions(s.Document)
			if ferr != nil {
				out["note"] = "session document has no function table: " + ferr.Error()
				return out, nil
			}
			if f := containingFunction(fns, s.Cursor); f != nil {
				out["procedure"] = f.Name
				out["procedure_entry"] = nativeHexAddr(f.Start)
				out["offset_in_function"] = s.Cursor - f.Start
			}
			return out, nil
		},
	})
}
