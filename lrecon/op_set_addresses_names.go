package main

import "fmt"

func init() {
	registerOp(op{
		name:  "set_addresses_names",
		route: "G",
		needs: true,
		desc:  "Name several addresses in one headless run: job \"labels\" ([{address,name}]) is applied in order and each result is reported.",
		run: func(path string) (any, error) {
			if s := ghidraGate(path); s != nil {
				return s, nil
			}
			job, err := opLoadJob(path)
			if err != nil {
				return nil, err
			}
			if len(job.Labels) == 0 {
				return nil, fmt.Errorf("set_addresses_names: job needs \"labels\" ([{address,name}])")
			}
			for i, l := range job.Labels {
				if l.Address == "" || l.Name == "" {
					return nil, fmt.Errorf("set_addresses_names: labels[%d] is not a pair of address and name", i)
				}
			}
			target, err := metaGhidraTarget(path, job)
			if err != nil {
				return nil, err
			}
			job.File = target
			kv := []string{"count", fmt.Sprintf("%d", len(job.Labels))}
			for i, l := range job.Labels {
				kv = append(kv, fmt.Sprintf("label.%d.address", i), l.Address, fmt.Sprintf("label.%d.name", i), l.Name)
			}
			return metaGhidraOp(job, "LABELS", metaArgs(kv...))
		},
	})
}
