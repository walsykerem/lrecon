package main

import "fmt"

func init() {
	registerOp(op{
		name:  "set_comment",
		route: "G",
		needs: true,
		desc:  "Set a pre-comment at an address (job {\"address\",\"text\"}) and report what the headless project stored for that address.",
		run: func(path string) (any, error) {
			if s := ghidraGate(path); s != nil {
				return s, nil
			}
			job, err := opLoadJob(path)
			if err != nil {
				return nil, err
			}
			if job.Address == "" || job.Text == "" {
				return nil, fmt.Errorf("set_comment: job needs \"address\" and \"text\"")
			}
			target, err := metaGhidraTarget(path, job)
			if err != nil {
				return nil, err
			}
			job.File = target
			return metaGhidraOp(job, "PRE", metaArgs("address", job.Address, "text", job.Text))
		},
	})
}
