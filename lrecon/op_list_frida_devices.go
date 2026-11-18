package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// 156. list_frida_devices — y34: EnumerateDevices(). frida-ls-devices drew two
// kinds of rows: the machine the tool runs on and the USB devices a
// frida-server could reach. Both are readable without frida: the host row is
// this machine, and the USB rows are the ones adb already tracks in
// `adb devices -l` (the same table list_adb_devices returns).
func init() {
	registerOp(op{
		name:  "list_frida_devices",
		route: "Y",
		desc:  "host row + `adb devices -l`: the device table frida would enumerate (final.md y34)",
		run:   opListFridaDevices,
	})
}

type rt2FridaDeviceList struct {
	Devices []rt2FridaDevice `json:"devices"`
	Count   int              `json:"count"`
	Note    string           `json:"note,omitempty"`
}

func opListFridaDevices(string) (any, error) {
	out, sk, err := rt2AdbRun("devices", "-l")
	if sk != nil || err != nil {
		return sk, err
	}
	devices := []rt2FridaDevice{rt2HostDevice()}
	var notes []string
	for _, d := range rtParseDevices(out) {
		name := d.Model
		if name == "" {
			name = d.Serial
		}
		devices = append(devices, rt2FridaDevice{ID: d.Serial, Type: "usb", Name: name, OS: "Android"})
		if d.State != "device" {
			notes = append(notes, fmt.Sprintf("%s is %q in adb, so it is listed but not attachable until it reports \"device\"", d.Serial, d.State))
		}
	}
	if len(devices) == 1 {
		notes = append(notes, "`adb devices -l` listed no rows: only the host row is real")
	}
	return rt2FridaDeviceList{Devices: devices, Count: len(devices), Note: strings.Join(notes, "; ")}, nil
}

// rt2HostDevice is the `local` row frida-ls-devices prints: the machine the
// tool runs on, named so a host row cannot be mistaken for a device serial.
func rt2HostDevice() rt2FridaDevice {
	name, err := os.Hostname()
	if err != nil || name == "" {
		name = "Local System"
	}
	return rt2FridaDevice{ID: "local", Type: "local", Name: name, OS: runtime.GOOS}
}
