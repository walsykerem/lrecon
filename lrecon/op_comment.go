package main

import (
	"fmt"
	"os"
	"strings"
)

func init() {
	registerOp(op{
		name:  "comment",
		route: "G",
		needs: true,
		desc:  "Set a plate comment at an address (job {\"address\",\"text\"}) and read the comment back from the headless project in the same 180 s run.",
		run: func(path string) (any, error) {
			if sk := ghidraGate(path); sk != nil {
				return sk, nil
			}
			// The target is the first problem, not the job fields: a path that is
			// not there was never read, so it keeps its io error instead of being
			// reported as a job that is missing "address"/"text".
			if _, err := os.Stat(path); err != nil {
				return nil, err
			}
			job, err := metaLoadJob(path)
			if err != nil {
				return nil, err
			}
			if job.Address == "" || job.Text == "" {
				return nil, fmt.Errorf("comment: job needs \"address\" and \"text\"")
			}
			target, err := metaGhidraTarget(path, job)
			if err != nil {
				return nil, err
			}
			job.File = target
			res, err := metaGhidraOp(job, "PLATE", metaArgs("address", job.Address, "text", job.Text))
			if err != nil {
				return nil, err
			}
			// metaGhidraPath's text offers to "set LRECON_GHIDRA / ...", which
			// classify() reads as needs_arg. An absent engine is no_engine, so the
			// refusal names the tool to install instead of an argument to supply.
			if s, ok := res.(*skip); ok && strings.Contains(s.Reason, "analyzeHeadless not found") {
				return skipf("%s", ghidraSkipReason()), nil
			}
			return res, nil
		},
	})
}
