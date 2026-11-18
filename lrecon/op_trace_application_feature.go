package main

import "fmt"

func init() {
	registerOp(op{
		name:  "trace_application_feature",
		route: "G",
		needs: true,
		desc:  "Trace a feature from one address through its callers inside a headless Ghidra project (job {\"address\",\"count\"}) and return the call chain.",
		run: func(path string) (any, error) {
			if s := ghidraGate(path); s != nil {
				return s, nil
			}
			job, err := opLoadJob(path)
			if err != nil {
				return nil, err
			}
			if job.Address == "" {
				return nil, fmt.Errorf("trace_application_feature: job needs \"address\"")
			}
			target, err := metaGhidraTarget(path, job)
			if err != nil {
				return nil, err
			}
			depth := "16"
			if job.Count > 0 {
				depth = fmt.Sprintf("%d", job.Count)
			}
			job.File = target
			return metaGhidraOp(job, "TRACE", metaArgs("address", job.Address, "count", depth))
		},
	})
}
