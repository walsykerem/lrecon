package main

// final.md: prev_address.
func init() {
	registerOp(op{
		name:  "prev_address",
		route: "L",
		desc:  "move the session cursor to the previous function start in the session document",
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
			f := prevFunction(fns, from)
			if f == nil {
				out["note"] = "no previous function start before the previous cursor"
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
