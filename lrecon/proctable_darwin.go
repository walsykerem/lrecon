//go:build darwin

package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"
)

// The kernel process table (kern.proc.all) is an array of kinfo_proc records.
// The layout below was measured on darwin/arm64 against `ps -axo pid=,comm=`
// (466 records, 466 unique pids, 0 pids ps does not know, 0 ps pids missing;
// the single miss was a racing exit). The record count varies with the number
// of live processes, the record layout does not.
const (
	darwinKinfoProcSize = 648
	darwinPidOffset     = 40 // kp_proc.p_pid, little-endian int32
	darwinCommOffset    = 243
	darwinCommLen       = 16 // p_comm, NUL padded
)

// findProcesses returns "<pid> <comm>" for every process whose command name
// matches name case-insensitively. Cutter sets its GUI binary name, so this
// replaces `pgrep -fl cutter` without running anything.
func findProcesses(name string) ([]string, error) {
	raw, err := syscall.Sysctl("kern.proc.all")
	if err != nil {
		return nil, fmt.Errorf("kern.proc.all: %w", err)
	}
	b := []byte(raw)
	if len(b) == 0 {
		return nil, errors.New("kern.proc.all returned no records")
	}
	// Sysctl drops one trailing NUL, so the buffer can end mid-record.
	if rem := len(b) % darwinKinfoProcSize; rem != 0 {
		b = append(b, make([]byte, darwinKinfoProcSize-rem)...)
	}
	// darwinProcMatches is the same decode plus the name filter, so the filter
	// has one definition instead of a copy per caller.
	out, plausible := darwinProcMatches(b, name)
	if plausible == 0 {
		return nil, errors.New("kern.proc.all: no plausible pid field, record layout differs on this host")
	}
	return out, nil
}

// listProcesses is the whole table, the same decode findProcesses filters, so
// `list_frida_processes` can answer for the host without spawning ps.
func listProcesses() ([]procRow, error) {
	raw, err := syscall.Sysctl("kern.proc.all")
	if err != nil {
		return nil, fmt.Errorf("kern.proc.all: %w", err)
	}
	b := []byte(raw)
	if len(b) == 0 {
		return nil, errors.New("kern.proc.all returned no records")
	}
	if rem := len(b) % darwinKinfoProcSize; rem != 0 {
		b = append(b, make([]byte, darwinKinfoProcSize-rem)...)
	}
	rows, plausible := darwinProcRows(b)
	if plausible == 0 {
		return nil, errors.New("kern.proc.all: no plausible pid field, record layout differs on this host")
	}
	return rows, nil
}

// darwinProcRows decodes the table and also reports how many records carried a
// plausible pid, so a layout drift is caught instead of looking like "not
// running".
func darwinProcRows(b []byte) (rows []procRow, plausible int) {
	rows = make([]procRow, 0, len(b)/darwinKinfoProcSize)
	for base := 0; base+darwinKinfoProcSize <= len(b); base += darwinKinfoProcSize {
		rec := b[base : base+darwinKinfoProcSize]
		pid := int(rec[darwinPidOffset]) | int(rec[darwinPidOffset+1])<<8 |
			int(rec[darwinPidOffset+2])<<16 | int(rec[darwinPidOffset+3])<<24
		if pid <= 0 || pid > 1<<24 {
			continue // unused tail slot
		}
		plausible++
		comm := strings.TrimSpace(string(rec[darwinCommOffset : darwinCommOffset+darwinCommLen]))
		if i := strings.IndexByte(comm, 0); i >= 0 {
			comm = strings.TrimSpace(comm[:i])
		}
		rows = append(rows, procRow{PID: pid, Comm: comm})
	}
	return rows, plausible
}

// darwinProcMatches is darwinProcRows plus the name filter findProcesses needs.
func darwinProcMatches(b []byte, name string) (out []string, plausible int) {
	rows, plausible := darwinProcRows(b)
	out = make([]string, 0, 8)
	for _, r := range rows {
		if strings.EqualFold(r.Comm, name) {
			out = append(out, strconv.Itoa(r.PID)+" "+r.Comm)
		}
	}
	return out, plausible
}
