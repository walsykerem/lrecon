package main

import "fmt"

func init() {
	registerOp(op{
		name:  "set_inline_comment",
		route: "G",
		needs: true,
		desc:  "Set an end-of-line comment for one address (job {\"address\",\"text\"}) and report the stored value; repeatable comments are not touched.",
		run: func(path string) (any, error) {
			if s := ghidraGate(path); s != nil {
				return s, nil
			}
			job, err := opLoadJob(path)
			if err != nil {
				return nil, err
			}
			if job.Address == "" || job.Text == "" {
				return nil, fmt.Errorf("set_inline_comment: job needs \"address\" and \"text\"")
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
