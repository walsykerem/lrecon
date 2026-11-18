package main

// final.md 62: inspect_native_api.
func init() {
	registerOp(op{
		name:  "inspect_native_api",
		route: "L",
		desc:  "imported API calls from the dynamic symbol/relocation, dyld or IAT tables, each with its slot address",
		needs: true,
		run: func(path string) (any, error) {
			kind, rows, err := nativeImports(path)
			if err != nil {
				return nil, err
			}
			shown := rows
			if len(shown) > nativeRowsCap {
				shown = shown[:nativeRowsCap]
			}
			ans := map[string]any{
				"format":  kind,
				"imports": len(rows),
				"shown":   len(shown),
				"rows":    shown,
			}
			if len(shown) < len(rows) {
				// The row cap hid part of the table: a gap is not a result, so
				// the answer says it is cut (same marker as list_strings).
				ans["truncated"] = true
			}
			if len(rows) == 0 {
				// A static image imports nothing: an empty table is the answer.
				ans["note"] = "target declares no imported symbols; the import table is empty"
			}
			return ans, nil
		},
	})
}
