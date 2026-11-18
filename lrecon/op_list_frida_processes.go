package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// 157. list_frida_processes — y35: Device.EnumerateProcesses(ScopeFull).
// frida-ps needed a frida-server on the target. Both halves are readable
// without frida: the host table comes from the kernel (no ps), and a USB
// device's table from `adb shell ps -A -o PID,NAME`.
func init() {
	registerOp(op{
		name:  "list_frida_processes",
		route: "Y",
		desc:  "host kernel table or `adb shell ps`: the processes frida would enumerate (final.md y35)",
		run:   opListFridaProcesses,
	})
}

type rt2FridaProcessList struct {
	Device     string            `json:"device"`
	DeviceType string            `json:"device_type"`
	Note       string            `json:"note,omitempty"`
	Processes  []rt2FridaProcess `json:"processes"`
	Count      int               `json:"count"`
}

func opListFridaProcesses(string) (any, error) {
	out, sk, err := rt2AdbRun("devices", "-l")
	if err != nil {
		return nil, err
	}
	var serial, note string
	if sk != nil {
		note = "adb is not installed, so the host table is the only one reachable: " + sk.Reason
	} else {
		var states []string
		for _, d := range rtParseDevices(out) {
			if d.State == "device" && serial == "" {
				serial = d.Serial
				continue
			}
			if d.State != "device" {
				states = append(states, d.Serial+" is "+d.State)
			}
		}
		if serial == "" {
			// Join only when there is a row to name: the sentence ended in a
			// dangling "; " on a host with an empty device table.
			note = "no device in state \"device\": the host table answers"
			if len(states) > 0 {
				note += "; " + strings.Join(states, ", ")
			}
		}
	}
	if serial == "" {
		return rt2HostProcessList(note)
	}
	// The serial that was just picked has to travel with the shell call: with
	// two devices attached `adb shell` refuses to guess (`more than one
	// device/emulator`) and the table would be lost on a host that has one.
	psOut, psk, err := rt2AdbRun("-s", serial, "shell", "ps", "-A", "-o", "PID,NAME")
	if psk != nil {
		return rt2HostProcessList(psk.Reason)
	}
	if err != nil {
		return nil, err
	}
	ps := rt2ParseAdbPS(psOut)
	if len(ps) == 0 {
		return nil, fmt.Errorf("`adb shell ps -A -o PID,NAME` output is not a process table (first line %q)", rt2FirstLine(psOut))
	}
	return rt2FridaProcessList{Device: serial, DeviceType: "usb", Note: "process table read with `adb shell ps -A -o PID,NAME`", Processes: ps, Count: len(ps)}, nil
}

// rt2HostProcessList answers for this machine: the kernel table, sorted by pid
// so two runs of the tool agree.
func rt2HostProcessList(note string) (rt2FridaProcessList, error) {
	rows, err := listProcesses()
	if err != nil {
		return rt2FridaProcessList{}, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].PID < rows[j].PID })
	ps := make([]rt2FridaProcess, 0, len(rows))
	for _, r := range rows {
		ps = append(ps, rt2FridaProcess{PID: r.PID, Name: r.Comm})
	}
	if note == "" {
		note = "host kernel process table (kern.proc.all on darwin, /proc on linux)"
	}
	return rt2FridaProcessList{Device: "local", DeviceType: "local", Note: note, Processes: ps, Count: len(ps)}, nil
}

// rt2ParseAdbPS reads the device's `ps` table through the same layout
// detection as list_adb_processes, so the two op families cannot disagree
// about which column is the pid on a legacy `USER PID PPID … NAME` table.
func rt2ParseAdbPS(out string) []rt2FridaProcess {
	ps := []rt2FridaProcess{}
	_, rows := adbPSTable(out)
	for _, r := range rows {
		pid, err := strconv.Atoi(r.PID)
		if err != nil || pid <= 0 || r.Name == "" {
			continue
		}
		ps = append(ps, rt2FridaProcess{PID: pid, Name: r.Name})
	}
	return ps
}
