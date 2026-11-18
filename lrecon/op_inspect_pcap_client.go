package main

import (
	"fmt"
	"strconv"
	"strings"
)

// final.md 31: inspect_pcap_client.
func init() {
	registerOp(op{
		name:  "inspect_pcap_client",
		route: "L",
		desc:  "HTTP request fingerprint (user agent, host, header order) and TLS ClientHello JA3 from the same flows",
		needs: true,
		run:   runInspectPcapClient,
	})
}

type netcHTTPClient struct {
	Frame       int      `json:"first_frame"`
	Src         string   `json:"src"`
	SrcPort     int      `json:"src_port"`
	Dst         string   `json:"dst"`
	DstPort     int      `json:"dst_port"`
	Host        string   `json:"host"`
	Method      string   `json:"method"`
	Target      string   `json:"target"`
	UserAgent   string   `json:"user_agent"`
	Accept      string   `json:"accept,omitempty"`
	AcceptLang  string   `json:"accept_language,omitempty"`
	AcceptEnc   string   `json:"accept_encoding,omitempty"`
	HeaderOrder []string `json:"header_order"`
	Family      string   `json:"family"`
	Count       int      `json:"requests"`
}

type netcTLSClient struct {
	Frame   int      `json:"first_frame"`
	Src     string   `json:"src"`
	SrcPort int      `json:"src_port"`
	Dst     string   `json:"dst"`
	DstPort int      `json:"dst_port"`
	SNI     string   `json:"sni,omitempty"`
	ALPN    []string `json:"alpn,omitempty"`
	Version uint16   `json:"version"`
	JA3     string   `json:"ja3"`
	JA3MD5  string   `json:"ja3_md5"`
	Family  string   `json:"family"`
	Count   int      `json:"hellos"`
}

// netcClientFamily names the stack from the values it actually sends, "-" when
// nothing in the handshake is distinctive. It is a label on top of the raw
// fingerprint, never a replacement for it.
func netcClientFamily(ua, ja3md5 string) string {
	low := strings.ToLower(ua)
	for _, c := range []struct{ prefix, family string }{
		{"curl/", "curl"},
		{"wget/", "wget"},
		{"python-requests/", "python-requests"},
		{"python-urllib/", "python-urllib"},
		{"go-http-client/", "go"},
		{"okhttp/", "okhttp"},
		{"cfnetwork/", "cfnetwork"},
		{"postmanruntime/", "postman"},
		{"libwww-perl/", "perl"},
		{"java/", "java"},
		{"mozilla/5.0", "browser"},
	} {
		if strings.HasPrefix(low, c.prefix) {
			return c.family
		}
	}
	if ua != "" {
		return "other"
	}
	// No request line at all: the TLS stack is the only evidence left.
	switch ja3md5 {
	case "cd08e31494f9531f560d64c695473da9", "b32309a26951912be7dba376398abc3b":
		return "mozilla-tls"
	case "3b5074b1b5d032e5620f69f9f700ff0e":
		return "curl-tls"
	case "c12f54a3f91dc7bafd92cb59fe009a35":
		return "go-tls"
	}
	return "-"
}

func runInspectPcapClient(path string) (any, error) {
	var httpRows []*netcHTTPClient
	var tlsRows []*netcTLSClient
	httpSeen := map[string]*netcHTTPClient{}
	tlsSeen := map[string]*netcTLSClient{}
	// A row is one client seen talking to one server: the fingerprint alone is
	// not the key, or two hosts would share a row and the dst/host columns would
	// describe only the first of them.
	var httpDropped, tlsDropped int
	info, err := netcReadCapture(path, netcFrameCap, func(f netcFrame) error {
		p := netcDecode(f)
		switch {
		case p.HTTP != nil && p.TCP != nil:
			key := p.IP.Dst + "\x00" + strconv.Itoa(p.TCP.DstPort) + "\x00" +
				p.HTTP.header("Host") + "\x00" +
				strings.Join(p.HTTP.HeaderOrder, "|") + "\x00" + p.HTTP.header("User-Agent")
			if row, ok := httpSeen[key]; ok {
				row.Count++
			} else if len(httpRows) < 100 {
				row = &netcHTTPClient{
					Frame: p.Frame, Src: p.IP.Src, SrcPort: p.TCP.SrcPort,
					Dst: p.IP.Dst, DstPort: p.TCP.DstPort,
					Host: p.HTTP.header("Host"), Method: p.HTTP.Method, Target: p.HTTP.Target,
					UserAgent: p.HTTP.header("User-Agent"), Accept: p.HTTP.header("Accept"),
					AcceptLang: p.HTTP.header("Accept-Language"), AcceptEnc: p.HTTP.header("Accept-Encoding"),
					HeaderOrder: p.HTTP.HeaderOrder, Count: 1,
				}
				row.Family = netcClientFamily(row.UserAgent, "")
				httpSeen[key] = row
				httpRows = append(httpRows, row)
			} else {
				httpDropped++
			}
		case p.TLS != nil && p.TCP != nil:
			key := p.IP.Dst + "\x00" + strconv.Itoa(p.TCP.DstPort) + "\x00" +
				p.TLS.SNI + "\x00" + p.TLS.JA3MD5
			if row, ok := tlsSeen[key]; ok {
				row.Count++
			} else if len(tlsRows) < 100 {
				row := &netcTLSClient{
					Frame: p.Frame, Src: p.IP.Src, SrcPort: p.TCP.SrcPort,
					Dst: p.IP.Dst, DstPort: p.TCP.DstPort,
					SNI: p.TLS.SNI, ALPN: p.TLS.ALPN, Version: p.TLS.Version,
					JA3: p.TLS.JA3, JA3MD5: p.TLS.JA3MD5, Count: 1,
				}
				row.Family = netcClientFamily("", p.TLS.JA3MD5)
				tlsSeen[key] = row
				tlsRows = append(tlsRows, row)
			} else {
				tlsDropped++
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if info.Packets == 0 {
		return nil, fmt.Errorf("%s is a %s capture but has no packets", path, info.Format)
	}
	if httpRows == nil {
		httpRows = []*netcHTTPClient{}
	}
	if tlsRows == nil {
		tlsRows = []*netcTLSClient{}
	}
	out := map[string]any{
		"capture":      info,
		"http_clients": httpRows,
		"tls_clients":  tlsRows,
	}
	if len(httpRows) == 0 && len(tlsRows) == 0 {
		out["note"] = fmt.Sprintf("%d packets, none carrying an HTTP/1.x request head or a TLS ClientHello", info.Packets)
	}
	if httpDropped+tlsDropped > 0 {
		out["truncated"] = fmt.Sprintf("%d further HTTP and %d further TLS flows are past the 100-row cap and not listed", httpDropped, tlsDropped)
	}
	return out, nil
}
