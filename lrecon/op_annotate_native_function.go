package main

import "fmt"

func init() {
	registerOp(op{
		name:  "annotate_native_function",
		route: "G",
		needs: true,
		desc:  "Annotate the function that contains an address with a plate comment (job {\"address\",\"text\"}) inside one 180 s headless Ghidra project.",
		run: func(path string) (any, error) {
			if sk := ghidraGate(path); sk != nil {
				return sk, nil
			}
			job, err := metaLoadJob(path)
			if err != nil {
				return nil, err
			}
			if job.Address == "" || job.Text == "" {
				return nil, fmt.Errorf("annotate_native_function: job needs \"address\" and \"text\"")
			}
			target, err := metaGhidraTarget(path, job)
			if err != nil {
				return nil, err
			}
			job.File = target
			return metaGhidraOp(job, "ANNOTATE", metaArgs("address", job.Address, "text", job.Text))
		},
	})
}
