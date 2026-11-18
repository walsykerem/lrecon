package main

// final.md 67: list_documents.
func init() {
	registerOp(op{
		name:  "list_documents",
		route: "L",
		desc:  "every document the session has opened, each with an exists/size check",
		needs: false,
		run: func(path string) (any, error) {
			s, err := sessionFor("")
			if err != nil {
				return nil, err
			}
			rows := make([]map[string]any, 0, len(s.Documents))
			for _, d := range s.Documents {
				row := map[string]any{"path": d, "selected": d == s.Document}
				if st, serr := nativeStat(d); serr != nil {
					row["exists"] = false
					row["error"] = serr.Error()
				} else {
					row["exists"] = true
					row["size"] = st.Size()
				}
				rows = append(rows, row)
			}
			return map[string]any{
				"project":   s.Project,
				"document":  s.Document,
				"documents": rows,
				"session":   sessionPath(),
			}, nil
		},
	})
}
