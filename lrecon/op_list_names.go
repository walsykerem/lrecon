package main

// final.md 68: list_names.
func init() {
	registerOp(op{
		name:  "list_names",
		route: "G",
		desc:  "symbol count with a bounded address/name/type sample from the database (ghidra headless)",
		needs: true,
		run: func(path string) (any, error) {
			res, err := ghidraOp(path, "list_names")
			if err != nil {
				return nil, err
			}
			return listNamesAnswer(res), nil
		},
	})
}

// listNamesAnswer names the two numbers the ghidra answer mixes. `names` is
// how many symbols the reader found; `sample` is the bounded set of rows it
// printed (NativeOp.java keeps SAMPLE=200 of them). The printed row count read
// as "how many names exist" understated the table by the sample cap and the cut
// answer looked complete, so the found count is published as `parsed`, the
// printed count as `shown`, and the cut as `truncated`.
//
// `total` is the same found count under the key the shared cap reader
// (capState) looks for, so the coverage envelope reports the names the answer
// did not list as skipped instead of claiming it parsed the whole table.
func listNamesAnswer(res any) any {
	m, ok := res.(map[string]any)
	if !ok {
		return res
	}
	found, _ := jsonInt(m["names"])
	rows, _ := m["sample"].([]any)
	m["parsed"] = found
	m["total"] = found
	m["shown"] = len(rows)
	m["truncated"] = found > len(rows)
	return m
}
