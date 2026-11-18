package main

import "testing"

// Synthetic headers only: both formats are a fixed header plus an opaque
// prototype tree, so the builders mirror lundump.h / lj_bcdump.h instead of
// shipping a fixture binary.

// luaPrefix is the 12-byte prefix shared by 5.2-5.4: signature, version,
// format, endianness, then the five target word sizes (int, size_t,
// Instruction, lua_Integer, lua_Number).
func luaPrefix(ver byte) []byte {
	return []byte{0x1b, 'L', 'u', 'a', ver, 0, 1, 4, 8, 4, 8, 8}
}

// lua51 is a 5.1 header: prefix, four sizes (no lua_Integer), then the
// integral-number flag.
func lua51() []byte {
	return append([]byte("\x1bLua\x51\x00\x01\x04\x08\x04\x08\x00"), 0, 0, 0, 0)
}

// lua52 ends at LUAC_DATA; the prototype tree follows immediately.
func lua52() []byte {
	return append(append(luaPrefix(0x52), luaCheck...), 0, 0, 0, 0)
}

// lua5x is a 5.3/5.4 header: the prefix, LUAC_DATA, then the little-endian
// sentinels 0x5678 and 370.5.
func lua5x(ver byte) []byte {
	b := append(luaPrefix(ver), luaCheck...)
	b = append(b, 0x78, 0x56, 0, 0, 0, 0, 0, 0)    // LUAC_INT
	b = append(b, 0, 0, 0, 0, 0, 0x28, 0x77, 0x40) // LUAC_NUM
	return append(b, 0, 0, 0, 0)
}

func TestLuaVersions(t *testing.T) {
	cases := []struct {
		name      string
		blob      []byte
		toolchain string
		wantSkip  string
		caps      []string
	}{
		{"5.1.luac", lua51(), "lua 5.1", "luaproto-version-unverified", []string{"lua:version=5.1", "lua:endianness=little", "lua:number=8", "lua:number_integral=false"}},
		{"5.2.luac", lua52(), "lua 5.2", "", []string{"lua:version=5.2", "lua:integer=8"}},
		{"5.3.luac", lua5x(0x53), "lua 5.3", "", []string{"lua:version=5.3", "lua:instruction=4", "lua:integer=8"}},
		{"5.4.luac", lua5x(0x54), "lua 5.4", "", []string{"lua:version=5.4", "lua:size_t=8"}},
		{"jit20.luac", []byte{0x1b, 'L', 'J', 1, 0x02}, "luajit 2.0", "", []string{"luajit:version=2.0", "luajit:strip"}},
		{"jit21.luac", []byte{0x1b, 'L', 'J', 2, 0x16}, "luajit 2.1", "", []string{"luajit:version=2.1", "luajit:strip", "luajit:ffi", "luajit:bitop"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := Probe(writeTemp(t, c.name, c.blob))
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if d.Kind != "lua" || d.Format != "lua" {
				t.Fatalf("kind/format = %q/%q, want lua/lua", d.Kind, d.Format)
			}
			if d.Toolchain != c.toolchain {
				t.Fatalf("toolchain = %q, want %q", d.Toolchain, c.toolchain)
			}
			if d.Coverage == nil || d.Coverage.Parsed != 1 {
				t.Fatalf("coverage = %+v, want one parsed header", d.Coverage)
			}
			if len(d.Skipped) != 0 {
				if len(d.Skipped) != 1 || d.Skipped[0].Reason != c.wantSkip {
					t.Fatalf("skipped = %+v, want %q", d.Skipped, c.wantSkip)
				}
			}
			for _, want := range c.caps {
				if !containsStr(d.Capabilities, want) {
					t.Fatalf("capabilities = %v, want %q", d.Capabilities, want)
				}
			}
		})
	}
}

func TestLuaRefusals(t *testing.T) {
	badData := lua5x(0x53)
	badData[luaDataOff] = 0
	badInt := lua5x(0x53)
	badInt[18] = 0
	badSize := lua5x(0x53)
	badSize[9] = 3 // Instruction size is always 4
	cases := []struct {
		name string
		blob []byte
		want string
	}{
		{"short", []byte("\x1bLua\x53"), "lua-truncated"},
		{"short51", []byte("\x1bLua\x51\x00\x01\x04\x08"), "lua-truncated"},
		{"version", []byte("\x1bLua\x55\x00"), "lua-version-unverified"},
		{"format", []byte("\x1bLua\x54\x01"), "lua-header-unverified"},
		{"endian-short", []byte("\x1bLua\x54\x00"), "lua-truncated"},
		{"data", badData, "lua-header-unverified"},
		{"sizes", badSize, "lua-header-unverified"},
		{"sentinel-int", badInt, "lua-header-unverified"},
		{"jit-short", []byte("\x1bLJ\x02"), "luajit-truncated"},
		{"jit-version", []byte("\x1bLJ\x03\x00"), "luajit-version-unverified"},
		{"jit-flags", []byte("\x1bLJ\x02\x80"), "luajit-flags-unverified"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := Probe(writeTemp(t, c.name+".luac", c.blob))
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if d.Kind != "lua" {
				t.Fatalf("kind = %q, want lua", d.Kind)
			}
			if len(d.Skipped) != 1 || d.Skipped[0].Reason != c.want {
				t.Fatalf("skipped = %+v, want %q", d.Skipped, c.want)
			}
		})
	}
}

// A head that only resembles the magic must not be claimed by this reader:
// another format's dispatch must still get the file.
func TestLuaNotClaimed(t *testing.T) {
	for _, h := range []string{"\x1bLu", "\x1bLX", "Lua", "\x1bL"} {
		d := Digest{Kind: "unknown"}
		if dispatch("plain.bin", []byte(h), int64(len(h)), &d) {
			t.Fatalf("head %q claimed", h)
		}
		if d.Format != "" || len(d.Skipped) != 0 {
			t.Fatalf("head %q changed digest: %+v", h, d)
		}
	}
}
