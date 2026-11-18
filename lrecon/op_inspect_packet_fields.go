package main

import "fmt"

// final.md 30: inspect_packet_fields.
func init() {
	registerOp(op{
		name:  "inspect_packet_fields",
		route: "L",
		desc:  "decode every captured frame down to L2/L3/L4 fields, plus DNS questions, TLS SNI and the HTTP request head",
		needs: true,
		run:   runInspectPacketFields,
	})
}

func runInspectPacketFields(path string) (any, error) {
	frames := make([]netcPacket, 0, 32)
	app := map[string]int{"dns": 0, "tls": 0, "http": 0}
	info, err := netcReadCapture(path, netcFrameCap, func(f netcFrame) error {
		p := netcDecode(f)
		switch {
		case p.DNS != nil:
			app["dns"]++
		case p.TLS != nil:
			app["tls"]++
		case p.HTTP != nil:
			app["http"]++
		}
		frames = append(frames, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if info.Packets == 0 {
		return nil, fmt.Errorf("%s is a %s capture but has no packets", path, info.Format)
	}
	out := map[string]any{
		"capture": info,
		"frames":  frames,
		"app":     app,
	}
	if info.CapHit {
		out["note"] = fmt.Sprintf("only the first %d of %d packets are decoded", netcFrameCap, info.Packets)
	}
	return out, nil
}
