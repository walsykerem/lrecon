package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"
)

// final.md: inspect_sqlite_database.
func init() {
	registerOp(op{
		name:  "inspect_sqlite_database",
		route: "L",
		desc:  "sqlite header facts (page size, writing library, WAL) plus the tables and CREATE statements in sqlite_master",
		needs: true,
		run: func(path string) (any, error) {
			d, err := Probe(path)
			if err != nil {
				return nil, err
			}
			if d.Kind != "sqlite" {
				return skipf("%s: %s is not a sqlite database", path, d.Kind), nil
			}
			if d.SQLitePageSize == 0 {
				return skipf("%s: sqlite header truncated, no page size in the first 100 bytes", path), nil
			}
			tables, err := sqliteTables(path)
			notes := make([]string, 0, len(d.Notes)+2)
			for _, n := range d.Notes {
				if !strings.HasPrefix(n, "deep:") {
					notes = append(notes, n)
				}
			}
			switch {
			case err != nil:
				// The header facts are still true; a schema that cannot be read
				// is a note, not a failed op.
				notes = append(notes, "table list not read: "+err.Error())
			case len(tables) > 0:
				notes = append(notes, "tables and CREATE statements come from sqlite_master; row contents are not returned")
			}
			return struct {
				PageSize      int           `json:"page_size"`
				Version       string        `json:"version"`
				WAL           bool          `json:"wal"`
				FileSize      int64         `json:"file_size"`
				Tables        []sqliteTable `json:"tables"`
				VirtualTables int           `json:"virtual_tables"`
				Notes         []string      `json:"notes,omitempty"`
			}{d.SQLitePageSize, d.SQLiteVersion, d.SQLiteWAL, d.FileSize, tables, sqliteVirtualTables(tables), notes}, nil
		},
	})
}

type sqliteTable struct {
	Name     string `json:"name"`
	RootPage int    `json:"root_page"`
	SQL      string `json:"sql,omitempty"`
}

// sqliteVirtualTables counts CREATE VIRTUAL TABLE rows in sqlite_master. Their
// rows live in shadow tables the b-tree walk never follows, so the count says
// what the schema admits without pretending the contents were read.
func sqliteVirtualTables(tables []sqliteTable) int {
	n := 0
	for _, t := range tables {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(t.SQL)), "CREATE VIRTUAL TABLE") {
			n++
		}
	}
	return n
}

// sqliteTables walks sqlite_master (root page 1) as a table b-tree. The header
// digest has no table names, and shelling out to sqlite3 would make the answer
// depend on an installed tool, so the pages are read directly.
func sqliteTables(path string) ([]sqliteTable, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	head, err := io.ReadAll(io.LimitReader(f, 100))
	if err != nil {
		return nil, err
	}
	if len(head) < 100 {
		return nil, fmt.Errorf("header is %d bytes, not the 100 a sqlite file starts with", len(head))
	}
	pageSize := int(binary.BigEndian.Uint16(head[16:18]))
	if pageSize == 1 {
		pageSize = 65536
	}
	if pageSize < 512 || pageSize > 65536 || pageSize&(pageSize-1) != 0 {
		return nil, fmt.Errorf("page size %d is not a power of two between 512 and 65536", pageSize)
	}
	usable := pageSize - int(head[20])
	if usable < 480 {
		return nil, fmt.Errorf("usable page size %d is below the sqlite minimum", usable)
	}
	r := &sqliteReader{f: f, pageSize: pageSize, usable: usable}
	rows, err := r.rows(1)
	if err != nil {
		return nil, err
	}
	tables := []sqliteTable{}
	for _, row := range rows {
		if len(row) < 5 {
			return nil, fmt.Errorf("sqlite_master row has %d columns, expected at least 5", len(row))
		}
		kind := sqliteText(row[0])
		if kind != "table" && kind != "view" {
			continue
		}
		tables = append(tables, sqliteTable{
			Name:     sqliteText(row[1]),
			RootPage: int(sqliteInt(row[3])),
			SQL:      sqliteText(row[4]),
		})
	}
	sort.Slice(tables, func(i, j int) bool { return tables[i].Name < tables[j].Name })
	return tables, nil
}

type sqliteReader struct {
	f        *os.File
	pageSize int
	usable   int
	seen     map[int]bool
}

func (r *sqliteReader) page(n int) ([]byte, error) {
	if n < 1 {
		return nil, fmt.Errorf("page number %d is not valid", n)
	}
	sr := io.NewSectionReader(r.f, int64(n-1)*int64(r.pageSize), int64(r.pageSize))
	b, err := io.ReadAll(io.LimitReader(sr, int64(r.pageSize)))
	if err != nil {
		return nil, fmt.Errorf("page %d: %w", n, err)
	}
	if len(b) < r.pageSize {
		return nil, fmt.Errorf("page %d is %d bytes, past the end of the file", n, len(b))
	}
	return b, nil
}

// rows returns every row of the table b-tree rooted at root.
func (r *sqliteReader) rows(root int) ([][]any, error) {
	if r.seen == nil {
		r.seen = map[int]bool{}
	}
	var out [][]any
	var walk func(int, int) error
	walk = func(pg, depth int) error {
		if depth > 64 {
			return fmt.Errorf("b-tree is deeper than 64 pages (cycle or corrupt child pointer)")
		}
		if r.seen[pg] {
			return fmt.Errorf("page %d is visited twice (cycle in the b-tree)", pg)
		}
		r.seen[pg] = true
		b, err := r.page(pg)
		if err != nil {
			return err
		}
		h := 0
		if pg == 1 {
			h = 100 // file header is part of page 1
		}
		if h+12 > len(b) {
			return fmt.Errorf("page %d is shorter than its b-tree header", pg)
		}
		ncell := int(binary.BigEndian.Uint16(b[h+3 : h+5]))
		switch b[h] {
		case 0x0d: // leaf table page
			if h+8+2*ncell > len(b) {
				return fmt.Errorf("page %d declares %d cells past the page", pg, ncell)
			}
			for i := range ncell {
				cell := int(binary.BigEndian.Uint16(b[h+8+2*i:]))
				if cell < h+8+2*ncell || cell >= len(b) {
					return fmt.Errorf("page %d cell %d starts at %d, outside the page", pg, i, cell)
				}
				size, n := sqliteVarint(b[cell:])
				_, n2 := sqliteVarint(b[cell+n:])
				rec, err := r.payload(pg, b, cell+n+n2, int(size))
				if err != nil {
					return fmt.Errorf("page %d cell %d: %w", pg, i, err)
				}
				row, err := sqliteRecord(rec)
				if err != nil {
					return fmt.Errorf("page %d cell %d: %w", pg, i, err)
				}
				out = append(out, row)
			}
		case 0x05: // interior table page
			if h+12+2*ncell > len(b) {
				return fmt.Errorf("page %d declares %d cells past the page", pg, ncell)
			}
			for i := range ncell {
				cell := int(binary.BigEndian.Uint16(b[h+12+2*i:]))
				if cell+4 > len(b) {
					return fmt.Errorf("page %d cell %d child pointer is past the page", pg, i)
				}
				if err := walk(int(binary.BigEndian.Uint32(b[cell:])), depth+1); err != nil {
					return err
				}
			}
			if err := walk(int(binary.BigEndian.Uint32(b[h+8:])), depth+1); err != nil {
				return err
			}
		default:
			return fmt.Errorf("page %d header type %#x is not a table b-tree page", pg, b[h])
		}
		return nil
	}
	if err := walk(root, 0); err != nil {
		return nil, err
	}
	return out, nil
}

// payload assembles one cell payload, following the overflow chain when the
// record does not fit on the leaf page.
func (r *sqliteReader) payload(pg int, page []byte, start, size int) ([]byte, error) {
	if size < 0 {
		return nil, fmt.Errorf("record payload size %d is negative", size)
	}
	x := r.usable - 35
	local := size
	if size > x {
		m := ((r.usable - 12) * 32 / 255) - 23
		k := m + ((size - m) % (r.usable - 4))
		if k <= x {
			local = k
		} else {
			local = m
		}
	}
	if start < 0 || start+local > len(page) {
		return nil, fmt.Errorf("record starts at %d with %d local bytes, past the %d-byte page", start, local, len(page))
	}
	// No preallocated buffer: the declared size is a varint from the file and
	// can claim far more than the page chain actually holds.
	var out []byte
	out = append(out, page[start:start+local]...)
	if local == size {
		return out, nil
	}
	if start+local+4 > len(page) {
		return nil, fmt.Errorf("overflow pointer is past the %d-byte page", len(page))
	}
	next := int(binary.BigEndian.Uint32(page[start+local:]))
	seen := map[int]bool{pg: true}
	for local < size {
		if next < 1 || seen[next] {
			return nil, fmt.Errorf("overflow chain points at page %d again", next)
		}
		seen[next] = true
		p, err := r.page(next)
		if err != nil {
			return nil, err
		}
		n := min(r.usable-4, size-local)
		out = append(out, p[4:4+n]...)
		local += n
		next = int(binary.BigEndian.Uint32(p))
	}
	return out, nil
}

func sqliteRecord(b []byte) ([]any, error) {
	n, k := sqliteVarint(b)
	hdrEnd := int(n) // the header size counts its own varint
	if n < 0 || hdrEnd < k || hdrEnd > len(b) {
		return nil, fmt.Errorf("record header is %d bytes, past the %d-byte payload", n, len(b))
	}
	var serials []int
	for p := k; p < hdrEnd; {
		t, m := sqliteVarint(b[p:hdrEnd])
		p += m
		serials = append(serials, int(t))
	}
	body := hdrEnd
	vals := make([]any, 0, len(serials))
	for _, t := range serials {
		v, n, err := sqliteValue(b[body:], t)
		if err != nil {
			return nil, err
		}
		body += n
		vals = append(vals, v)
	}
	return vals, nil
}

func sqliteValue(b []byte, serial int) (any, int, error) {
	switch serial {
	case 0:
		return nil, 0, nil
	case 1, 2, 3, 4, 5, 6:
		n := []int{0, 1, 2, 3, 4, 6, 8}[serial]
		if len(b) < n {
			return nil, 0, fmt.Errorf("integer of %d bytes is past the payload", n)
		}
		var v int64
		for _, c := range b[:n] {
			v = v<<8 | int64(c)
		}
		shift := uint(64 - 8*n)
		return v << shift >> shift, n, nil
	case 7:
		if len(b) < 8 {
			return nil, 0, fmt.Errorf("float is past the payload")
		}
		return math.Float64frombits(binary.BigEndian.Uint64(b[:8])), 8, nil
	case 8:
		return int64(0), 0, nil
	case 9:
		return int64(1), 0, nil
	case 10, 11:
		return nil, 0, fmt.Errorf("serial type %d is reserved", serial)
	}
	n := (serial - 12) / 2
	if serial%2 == 1 {
		n = (serial - 13) / 2
	}
	if n < 0 || len(b) < n {
		return nil, 0, fmt.Errorf("value of %d bytes is past the payload", n)
	}
	if serial%2 == 0 {
		return string(b[:n]), n, nil
	}
	return append([]byte(nil), b[:n]...), n, nil
}

// sqliteVarint decodes sqlite's big-endian base-128 integer: up to 9 bytes,
// where the ninth contributes all eight bits.
func sqliteVarint(b []byte) (int64, int) {
	var v uint64
	for i := 0; i < 9 && i < len(b); i++ {
		c := b[i]
		if i == 8 {
			v = v<<8 | uint64(c)
			return int64(v), 9
		}
		v = v<<7 | uint64(c&0x7f)
		if c&0x80 == 0 {
			return int64(v), i + 1
		}
	}
	if len(b) == 0 {
		return 0, 0
	}
	return int64(v), len(b)
}

func sqliteText(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	}
	return ""
}

func sqliteInt(v any) int64 {
	if n, ok := v.(int64); ok {
		return n
	}
	return 0
}
