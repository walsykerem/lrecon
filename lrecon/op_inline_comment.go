package main

import "fmt"

func init() {
	registerOp(op{
		name:  "inline_comment",
		route: "G",
		needs: true,
		desc:  "Set an end-of-line comment at an address (job {\"address\",\"text\"}) and report the stored comment from the headless project.",
		run: func(path string) (any, error) {
			// Parse the job before the gate: ghidraGate cannot extract "file" from
			// a wrong-shaped job, so it would mask the bad_arg as a text-kind skip.
			job, err := opLoadJob(path)
			if err != nil {
				return nil, err
			}
			if sk := ghidraGate(path); sk != nil {
				return sk, nil
			}
			if job.Address == "" || job.Text == "" {
				return nil, fmt.Errorf("inline_comment: job needs \"address\" and \"text\"")
			}
			target, err := metaGhidraTarget(path, job)
			if err != nil {
				return nil, err
			}
			job.File = target
			return metaGhidraOp(job, "EOL", metaArgs("address", job.Address, "text", job.Text))
		},
	})
}
