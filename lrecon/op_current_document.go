package main

// final.md 52: current_document.
func init() {
	registerOp(op{
		name:  "current_document",
		route: "L",
		desc:  "the document, project, cursor and known documents recorded in the session",
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
				"documents": len(s.Documents),
				"session":   sessionPath(),
			}
			if st, serr := nativeStat(s.Document); serr == nil {
				out["size"] = st.Size()
				out["modified"] = st.ModTime().UTC().Format("2006-01-02T15:04:05Z")
			}
			return out, nil
		},
	})
}
