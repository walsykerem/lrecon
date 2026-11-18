//go:build !darwin && !linux

package main

import (
	"fmt"
	"runtime"
)

// findProcesses has no in-process implementation outside darwin and linux:
// this build reports the gap instead of shelling out to pgrep/ps.
func findProcesses(name string) ([]string, error) {
	return nil, fmt.Errorf("process table lookup for %q is not implemented on %s", name, runtime.GOOS)
}

// listProcesses reports the same gap rather than pretending the host has no
// processes.
func listProcesses() ([]procRow, error) {
	return nil, fmt.Errorf("process table listing is not implemented on %s", runtime.GOOS)
}
