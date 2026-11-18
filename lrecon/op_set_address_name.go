package main

import "fmt"

func init() {
	registerOp(op{
		name:  "set_address_name",
		route: "G",
		needs: true,
		desc:  "Name the function at one address (job {\"address\",\"name\"}) in a headless project and report the name Ghidra stored.",
		run: func(path string) (any, error) {
			if s := ghidraGate(path); s != nil {
				return s, nil
			}
			job, err := opLoadJob(path)
			if err != nil {
				return nil, err
			}
			if job.Address == "" || job.Name == "" {
				return nil, fmt.Errorf("set_address_name: job needs \"address\" and \"name\"")
			}
			target, err := metaGhidraTarget(path, job)
			if err != nil {
				return nil, err
			}
			job.File = target
			return metaGhidraOp(job, "LABEL", metaArgs("address", job.Address, "name", job.Name))
		},
	})
}
