package main

// final.md 46: address_to_file_offset.
func init() {
	registerOp(op{
		name:  "address_to_file_offset",
		route: "G",
		desc:  "map LRECON_AT to its byte offset in the file through the block source map (ghidra headless)",
		needs: true,
		run: func(path string) (any, error) {
			addr, err := nativeAddrArg()
			if err != nil {
				return nil, err
			}
			at := nativeHexAddr(addr)
			res, err := ghidraOp(path, "address_to_file_offset", at)
			if err != nil {
				return res, err
			}
			return annotateFileOffset(path, addr, res), nil
		},
	})
}
