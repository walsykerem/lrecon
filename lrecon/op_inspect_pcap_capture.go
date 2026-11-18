package main

// final.md: inspect_pcap_capture. Same capture reader as inspect_packet_capture;
// both names are registry entries, so one implementation answers both.
func init() {
	registerOp(op{
		name:  "inspect_pcap_capture",
		route: "L",
		desc:  "pcap and pcapng container facts: file format, packet count, link type and capture span, plus the distinct protocol hints the same reader found",
		needs: true,
		run:   runInspectPacketCapture,
	})
}
