package main

func init() {
	registerOp(op{
		name:  "list_adb_devices",
		route: "Y",
		desc:  "attached device table from `adb devices -l` (serial, state, product, model, transport_id); no device needed to answer",
		run:   listADBDevices,
	})
}

// listADBDevices is §y y28: `host:devices-l` is what the CLI's `devices -l`
// asks for, so the parser is the same one every device op agrees with.
func listADBDevices(string) (any, error) {
	ctx, cancel := rtCtx()
	defer cancel()
	adb, sk := rtAdb()
	if sk != nil {
		return sk, nil
	}
	out, err := rtRun(ctx, adb, "devices", "-l")
	if err != nil {
		return nil, err
	}
	return rtParseDevices(out), nil
}
