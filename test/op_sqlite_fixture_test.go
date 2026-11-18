package main

// The committed database is the only sqlite input the parser sees end to end:
// header-only zero buffers never reach the record, varint or value code, so a
// parser that always answers "no tables" would still pass. These tests read
// testdata/fixtures/sqlite/fixture.db through the op, then feed the record
// decoder the value shapes the fixture does not carry (float, blob, zero/one,
// negative int, multi-byte varint).

import (
	"encoding/binary"
	"math"
	"strings"
	"testing"
)

func TestSqliteFixtureParsesRealSchema(t *testing.T) {
	got := reaDataJSON(t, "inspect_sqlite_database", "testdata/fixtures/sqlite/fixture.db")
	if n := a10Num(t, got, "page_size"); n != 4096 {
		t.Fatalf("page_size = %v, want 4096", n)
	}
	if n := a10Num(t, got, "file_size"); n != 12288 {
		t.Fatalf("file_size = %v, want 12288", n)
	}
	tables, ok := a10Get(t, got, "tables").([]any)
	if !ok || len(tables) != 2 {
		t.Fatalf("tables = %v, want 2 tables from sqlite_master", got["tables"])
	}
	for i, want := range []struct {
		name, sql string
		root      float64
	}{
		{"events", "CREATE TABLE events", 3},
		{"users", "CREATE TABLE users", 2},
	} {
		if name := a10Get(t, got, "tables", i, "name"); name != want.name {
			t.Fatalf("tables[%d].name = %v, want %s", i, name, want.name)
		}
		// root_page comes from sqliteInt over a real record body; 0 would mean
		// the value decoder never ran.
		if root := a10Num(t, got, "tables", i, "root_page"); root != want.root {
			t.Fatalf("tables[%d].root_page = %v, want %v", i, root, want.root)
		}
		sql, _ := a10Get(t, got, "tables", i, "sql").(string)
		if !strings.HasPrefix(sql, want.sql) {
			t.Fatalf("tables[%d].sql = %q, want prefix %q", i, sql, want.sql)
		}
	}
}

func rec(serials []byte, body []byte) []byte {
	b := append([]byte{byte(len(serials) + 1)}, serials...)
	return append(b, body...)
}

func TestSqliteRecordDecodesEveryValueShape(t *testing.T) {
	var floatBits [8]byte
	binary.BigEndian.PutUint64(floatBits[:], math.Float64bits(1.5))
	body := []byte{}
	body = append(body, 0, 0, 0, 0, 0, 42)  // serial 5: 6-byte int
	body = append(body, floatBits[:]...)    // serial 7: float
	body = append(body, 0xff, 0xff, 0xff)   // serial 3: 3-byte int, negative
	body = append(body, 'a', 'b', 'c', 'd') // serial 20: 4-byte text
	body = append(body, 0x7f)               // serial 14: 1-byte blob
	serials := []byte{0, 5, 7, 3, 8, 9, 20, 14, 12, 13}
	// null, int48, float, int24, zero, one, text, blob, empty blob, empty text
	vals, err := sqliteRecord(rec(serials, body))
	if err != nil {
		t.Fatalf("sqliteRecord: %v", err)
	}
	// sqliteValue returns a string for even serials and bytes for odd ones;
	// that is the reverse of the file format's blob/text split, but the op only
	// asks for text (sqliteText accepts both), so no answer depends on it.
	want := []any{nil, int64(42), 1.5, int64(-1), int64(0), int64(1), "abcd", "\x7f", "", []byte{}}
	if len(vals) != len(want) {
		t.Fatalf("got %d values, want %d: %v", len(vals), len(want), vals)
	}
	for i := range want {
		switch w := want[i].(type) {
		case []byte:
			got, ok := vals[i].([]byte)
			if !ok || string(got) != string(w) {
				t.Fatalf("value %d = %#v, want bytes %#v", i, vals[i], w)
			}
		default:
			if vals[i] != w {
				t.Fatalf("value %d = %#v, want %#v", i, vals[i], w)
			}
		}
	}
}

func TestSqliteRecordLongHeaderVarint(t *testing.T) {
	// A 200-byte text value puts serial 412 in the header, so the header walk
	// needs a two-byte varint instead of the one-byte kind the fixture has.
	text := strings.Repeat("x", 200)
	vals, err := sqliteRecord(rec([]byte{0x83, 0x1c}, []byte(text)))
	if err != nil {
		t.Fatalf("sqliteRecord: %v", err)
	}
	if len(vals) != 1 || sqliteText(vals[0]) != text {
		t.Fatalf("200-byte text did not survive the header varint: %#v", vals)
	}
	if n, size := sqliteVarint([]byte{0x87, 0xff, 0xff, 0xff, 0x7f}); n != 0x7fffffff || size != 5 {
		t.Fatalf("sqliteVarint(5-byte) = %d,%d, want %d,5", n, size, 0x7fffffff)
	}
	if n, size := sqliteVarint([]byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}); n != 1 || size != 9 {
		t.Fatalf("sqliteVarint(9-byte) = %d,%d, want 1,9", n, size)
	}
}
