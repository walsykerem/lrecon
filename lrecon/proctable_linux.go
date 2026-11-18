//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
)

// linuxProcRows reads /proc/<pid>/comm for every numeric /proc entry. A read
// that fails is a process that exited between listing and reading, not an
// error worth failing the whole table for.
func linuxProcRows() ([]procRow, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	rows := make([]procRow, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		digits := name != "" // /proc mixes pids with names like "self", "net", "sys"
		for i := 0; digits && i < len(name); i++ {
			digits = name[i] >= '0' && name[i] <= '9'
		}
		if !digits {
			continue
		}
		pid, err := strconv.Atoi(name)
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + name + "/comm")
		if err != nil {
			continue
		}
		rows = append(rows, procRow{PID: pid, Comm: strings.TrimSpace(string(b))})
	}
	return rows, nil
}

// findProcesses returns "<pid> <comm>" for every process whose command name
// matches name case-insensitively, read straight from /proc.
func findProcesses(name string) ([]string, error) {
	rows, err := linuxProcRows()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, 8)
	for _, r := range rows {
		if strings.EqualFold(r.Comm, name) {
			out = append(out, strconv.Itoa(r.PID)+" "+r.Comm)
		}
	}
	return out, nil
}

// listProcesses is the whole /proc table, the same read findProcesses filters,
// so `list_frida_processes` can answer for the host without spawning ps.
func listProcesses() ([]procRow, error) { return linuxProcRows() }
