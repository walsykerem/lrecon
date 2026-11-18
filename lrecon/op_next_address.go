package main

// final.md: next_address.
func init() {
	registerOp(op{
		name:  "next_address",
		route: "L",
		desc:  "move the session cursor to the next function start in the session document",
		needs: false,
		run: func(path string) (any, error) {
			s, err := sessionFor(path)
			if err != nil {
				return nil, err
			}
			fns, err := nativeFunctions(s.Document)
			if err != nil {
				return nil, err
			}
			from := s.Cursor
			out := map[string]any{
				"document": s.Document,
				"from":     nativeHexAddr(from),
				"found":    false,
			}
			f := nextFunction(fns, from)
			if f == nil {
				out["note"] = "no next function start after next cursor"
				return out, nil
			}
			s.Cursor = f.Start
			s.Procedure = f.Name
			if err := saveSession(s); err != nil {
				return nil, err
			}
			out["found"] = true
			out["to"] = nativeHexAddr(f.Start)
			out["procedure"] = f.Name
			out["end"] = nativeHexAddr(f.End)
			return out, nil
		},
	})
}
