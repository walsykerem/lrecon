package main

func init() {
	registerOp(op{
		name:  "list_unknowns",
		route: "G",
		needs: true,
		desc:  "List the functions Ghidra could not resolve (undefined/thunk bodies) with address and size, from one headless analysis of the target.",
		run: func(path string) (any, error) {
			job, err := metaLoadJob(path)
			if err != nil {
				return nil, err
			}
			target, err := metaGhidraTarget(path, job)
			if err != nil {
				return nil, err
			}
			job.File = target
			// Both G routes have to answer a missing analyzeHeadless the same
			// way. metaGhidraPath words it "analyzeHeadless not found: install
			// Ghidra, ...", which classify() reads as needs_arg: the caller is
			// told to pass an argument it already passed. ghidraOp prechecks for
			// the same reason (op_native_util.go), so this route does too. The
			// gate also keeps the order right: a managed assembly names its kind
			// even on a machine with no Ghidra.
			if s := ghidraGate(target); s != nil {
				return s, nil
			}
			return metaGhidraOp(job, "UNKNOWN", metaArgs())
		},
	})
}
