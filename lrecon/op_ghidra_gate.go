package main

import "os"

// ghidraGate refuses a route-G item before it resolves anything locally.
//
// The order is the contract: a path that is not on disk was never read, so it
// owes its io error before any engine claim — a caller sent to "install Ghidra"
// for a target that does not exist fixes the wrong thing. With the target in
// hand the item answers about the decompiler it needs, not about the argument
// it could not find: an item that checks LRECON_AT first reports bad_arg ("no
// function named 0x1000") for a machine that has no Ghidra at all. And a kind
// no decompiler can import is named before the missing tool, because installing
// Ghidra would not make bytecode decompilable.
//
// ghidraOp keeps its own gate; this one exists for the ops that resolve an
// address, a name or a job *before* they reach ghidraOp. Ghidra present -> nil,
// and the op goes on to its normal work.
func ghidraGate(path string) *skip {
	if path != "" {
		if _, err := os.Stat(path); err != nil {
			return nil // absent target: the op's own io error is the answer
		}
		if s := ghidraKindRefusal(ghidraGateTarget(path)); s != nil {
			return s
		}
	}
	if _, _, err := ghidraFinder(); err != nil {
		return skipf("%s: %v", ghidraSkipReason(), err)
	}
	return nil
}

// ghidraGateTarget is the artifact whose kind decides the refusal. The meta
// items are handed a job file, so the job's "file" is the target; probing the
// job's own JSON would call every meta item a text file.
func ghidraGateTarget(path string) string {
	if d, err := Probe(path); err != nil || d.Kind != "text" {
		return path
	}
	if job, err := metaLoadJob(path); err == nil && job.File != "" {
		return job.File
	}
	return path
}
