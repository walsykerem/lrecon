package main

// Fixtures for inspect_asset_catalog. The synthetic catalog is assembled byte by
// byte from the layout verified against a shipped macOS Assets.car: big-endian
// header, 8-byte index slots, var table, then self-describing blocks. The real
// system catalog is used when the machine has one, as a second opinion.

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// assetCatalogFixture writes a six-block BOMStore catalog:
// CARHEADER (RATC), RENDITIONS (tree -> one leaf pair -> ISTC), KEYFORMAT (tmfk).
func assetCatalogFixture(t *testing.T) string {
	t.Helper()
	hdr := make([]byte, 0x14+len("Test 1.0")+1)
	copy(hdr, "RATC")
	binary.LittleEndian.PutUint32(hdr[4:], 973) // coreuiVersion
	binary.LittleEndian.PutUint32(hdr[8:], 17)  // storageVersion
	copy(hdr[0x14:], "Test 1.0\x00")            // mainVersionString

	tree := make([]byte, 24)
	copy(tree, "tree")
	binary.BigEndian.PutUint32(tree[4:], 1)
	binary.BigEndian.PutUint32(tree[8:], 3) // root node lives in block 3
	binary.BigEndian.PutUint32(tree[12:], 4096)

	node := make([]byte, 20)
	binary.BigEndian.PutUint16(node[0:], 1)  // leaf node
	binary.BigEndian.PutUint16(node[2:], 1)  // one pair
	binary.BigEndian.PutUint32(node[12:], 4) // value: ISTC block
	binary.BigEndian.PutUint32(node[16:], 5) // key block

	istc := make([]byte, 0x28)
	copy(istc, "ISTC")

	key := []byte{0xde, 0xad, 0x00, 0x04, 0xbe, 0xef, 0x00, 0x02}

	kfmt := make([]byte, 20)
	copy(kfmt, "tmfk")
	binary.LittleEndian.PutUint32(kfmt[8:], 2)  // two key ids
	binary.LittleEndian.PutUint32(kfmt[12:], 1) // name
	binary.LittleEndian.PutUint32(kfmt[16:], 7) // one more key id

	blocks := [][]byte{{}, hdr, tree, node, istc, key, kfmt, {}}

	names := []string{"CARHEADER", "RENDITIONS", "KEYFORMAT"}
	ids := []uint32{1, 2, 6}
	var varsBody []byte
	for i, name := range names {
		varsBody = binary.BigEndian.AppendUint32(varsBody, ids[i])
		varsBody = append(varsBody, byte(len(name)))
		varsBody = append(varsBody, name...)
	}

	const headerLen, slotLen = 32, 8
	idxLen := 4 + slotLen*len(blocks) // 68: count plus one 8-byte slot per block
	varsLen := 4 + len(varsBody)      // 47: count, then id/name-length/name
	body := headerLen + idxLen + varsLen

	var tail []byte
	offs := make([]int, len(blocks))
	for i, blk := range blocks[1:] {
		offs[i+1] = body + len(tail)
		tail = append(tail, blk...)
	}

	img := make([]byte, body+len(tail))
	copy(img, "BOMStore")
	be := binary.BigEndian
	be.PutUint32(img[8:], 1)                         // version
	be.PutUint32(img[12:], 6)                        // blocks in use
	be.PutUint32(img[16:], headerLen)                // index offset
	be.PutUint32(img[20:], uint32(idxLen))           // index length
	be.PutUint32(img[24:], uint32(headerLen+idxLen)) // vars offset (100)
	be.PutUint32(img[28:], uint32(varsLen))          // vars length
	be.PutUint32(img[headerLen:], uint32(len(blocks)))
	for i, blk := range blocks {
		if i == 0 {
			continue // slot 0 stays empty, as in shipped catalogs
		}
		be.PutUint32(img[headerLen+4+8*i:], uint32(offs[i]))
		be.PutUint32(img[headerLen+8+8*i:], uint32(len(blk)))
	}
	varsAt := headerLen + idxLen
	be.PutUint32(img[varsAt:], uint32(len(names)))
	copy(img[varsAt+4:], varsBody)
	copy(img[body:], tail)
	return writeTemp(t, "Assets.car", img)
}

type assetCatalogOut struct {
	Container      string `json:"container"`
	Version        uint32 `json:"version"`
	BlocksDeclared uint32 `json:"blocks_declared"`
	IndexSlots     int    `json:"index_slots"`
	BlocksUsed     int    `json:"blocks_used"`
	Index          struct {
		Offset uint32 `json:"offset"`
		Length uint32 `json:"length"`
	} `json:"index"`
	Vars struct {
		Offset uint32 `json:"offset"`
		Length uint32 `json:"length"`
	} `json:"vars"`
	NamedBlocks []struct {
		Name   string `json:"name"`
		ID     uint32 `json:"id"`
		Offset uint32 `json:"offset"`
		Size   uint32 `json:"size"`
		Magic  string `json:"magic"`
	} `json:"named_blocks"`
	CoreuiVersion  uint32   `json:"coreui_version"`
	StorageVersion uint32   `json:"storage_version"`
	MainVersion    string   `json:"main_version"`
	KeyFormatIDs   []uint32 `json:"key_format_ids"`
	Trees          []struct {
		Name  string `json:"name"`
		Pairs int    `json:"pairs"`
	} `json:"trees"`
	Renditions     int            `json:"renditions"`
	RenditionBytes uint64         `json:"rendition_bytes"`
	BlockPrefixes  map[string]int `json:"block_prefixes"`
}

func TestAssetCatalogSynthetic(t *testing.T) {
	p := assetCatalogFixture(t)
	var res assetCatalogOut
	metaBRes(t, reaMobileRun(t, "inspect_asset_catalog", p), &res)

	if res.Container != "BOMStore" || res.Version != 1 {
		t.Fatalf("container = %q v%d", res.Container, res.Version)
	}
	if res.BlocksDeclared != 6 || res.IndexSlots != 8 || res.BlocksUsed != 6 {
		t.Fatalf("counts = declared %d, slots %d, used %d", res.BlocksDeclared, res.IndexSlots, res.BlocksUsed)
	}
	if res.Index.Offset != 32 || res.Index.Length != 68 || res.Vars.Offset != 100 || res.Vars.Length != 47 {
		t.Fatalf("tables = index %+v vars %+v", res.Index, res.Vars)
	}
	if res.CoreuiVersion != 973 || res.StorageVersion != 17 || res.MainVersion != "Test 1.0" {
		t.Fatalf("carheader = %d %d %q", res.CoreuiVersion, res.StorageVersion, res.MainVersion)
	}

	want := []struct {
		name  string
		id    uint32
		size  uint32
		magic string
	}{
		{"CARHEADER", 1, 0x14 + 8 + 1, "RATC"},
		{"KEYFORMAT", 6, 20, "tmfk"},
		{"RENDITIONS", 2, 24, "tree"},
	}
	if len(res.NamedBlocks) != len(want) {
		t.Fatalf("named blocks = %+v", res.NamedBlocks)
	}
	for i, w := range want {
		got := res.NamedBlocks[i]
		if got.Name != w.name || got.ID != w.id || got.Size != w.size || got.Magic != w.magic {
			t.Fatalf("named block %d = %+v, want %+v", i, got, w)
		}
		if got.Offset == 0 {
			t.Fatalf("named block %s has no offset", got.Name)
		}
	}

	if len(res.KeyFormatIDs) != 2 || res.KeyFormatIDs[0] != 1 || res.KeyFormatIDs[1] != 7 {
		t.Fatalf("key formats = %v", res.KeyFormatIDs)
	}
	if len(res.Trees) != 1 || res.Trees[0].Name != "RENDITIONS" || res.Trees[0].Pairs != 1 {
		t.Fatalf("trees = %+v", res.Trees)
	}
	if res.Renditions != 1 || res.RenditionBytes != 0x28 {
		t.Fatalf("renditions = %d, %d bytes", res.Renditions, res.RenditionBytes)
	}
	wantPrefixes := map[string]int{"RATC": 1, "tree": 1, "ISTC": 1, "tmfk": 1, "other": 2}
	if len(res.BlockPrefixes) != len(wantPrefixes) {
		t.Fatalf("block prefixes = %v", res.BlockPrefixes)
	}
	for k, n := range wantPrefixes {
		if res.BlockPrefixes[k] != n {
			t.Fatalf("block prefixes = %v, want %v", res.BlockPrefixes, wantPrefixes)
		}
	}
}

// TestAssetCatalogSystemCar: a shipped catalogs.car from a real app proves the
// reader on a file it did not author. The tracked fixture is a builder-made
// one, so this stays a host check and skips when no bundle is installed.
func TestAssetCatalogSystemCar(t *testing.T) {
	const car = "/System/Applications/Utilities/Activity Monitor.app/Contents/Resources/Assets.car"
	if _, err := os.Stat(car); err != nil {
		t.Skipf("no shipped asset catalog on this machine: %v", err)
	}
	var res assetCatalogOut
	metaBRes(t, reaMobileRun(t, "inspect_asset_catalog", car), &res)

	if res.Container != "BOMStore" || res.Version != 1 {
		t.Fatalf("container = %q v%d", res.Container, res.Version)
	}
	if res.IndexSlots <= 0 || res.BlocksUsed <= 0 || res.BlocksUsed > res.IndexSlots {
		t.Fatalf("counts = slots %d, used %d", res.IndexSlots, res.BlocksUsed)
	}
	// The tree walk is the count: one ISTC block per RENDITIONS leaf.
	if res.Renditions <= 0 || res.BlockPrefixes["ISTC"] != res.Renditions {
		t.Fatalf("renditions = %d, ISTC blocks = %d", res.Renditions, res.BlockPrefixes["ISTC"])
	}
	if res.RenditionBytes == 0 || len(res.KeyFormatIDs) == 0 {
		t.Fatalf("rendition bytes = %d, key formats = %v", res.RenditionBytes, res.KeyFormatIDs)
	}
	if len(res.Trees) == 0 || res.Trees[0].Name != "RENDITIONS" || res.Trees[0].Pairs != res.Renditions {
		t.Fatalf("trees = %+v", res.Trees)
	}
	blocks := map[string]string{}
	for _, nb := range res.NamedBlocks {
		blocks[nb.Name] = nb.Magic
	}
	if blocks["CARHEADER"] != "RATC" || blocks["RENDITIONS"] != "tree" || blocks["KEYFORMAT"] != "tmfk" {
		t.Fatalf("named block magics = %v", blocks)
	}
}

func TestAssetCatalogRefusals(t *testing.T) {
	dir := t.TempDir()
	apk := filepath.Join(dir, "app.apk")
	reaMobileZip(t, apk, map[string]string{"AndroidManifest.xml": "<manifest/>"})
	if reason := reaMobileSkip(t, "inspect_asset_catalog", apk); !strings.Contains(reason, "Android package") {
		t.Fatalf("apk skip = %q", reason)
	}

	text := reaMobileText(t, dir, "note.txt")
	if reason := reaMobileSkip(t, "inspect_asset_catalog", text); !strings.Contains(reason, "not an asset catalog") {
		t.Fatalf("text skip = %q", reason)
	}

	carv := writeTemp(t, "chunks.car", append([]byte("CARV"), make([]byte, 8)...))
	if reason := reaMobileSkip(t, "inspect_asset_catalog", carv); !strings.Contains(reason, "asset catalog parsing not implemented") || !strings.Contains(reason, "CARV") {
		t.Fatalf("CARV skip = %q", reason)
	}

	if _, err := runOp("inspect_asset_catalog", writeTemp(t, "cut.car", []byte("BOMStore but far too short"))); err == nil {
		t.Fatal("a truncated BOM header must be an error, not a partial catalog")
	}
}

// assetCatalogMutate patches the fixture image and asks the op to parse it.
func assetCatalogMutate(t *testing.T, edit func(img []byte)) error {
	t.Helper()
	img, err := os.ReadFile(assetCatalogFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	edit(img)
	_, err = runOp("inspect_asset_catalog", writeTemp(t, "mut.car", img))
	return err
}

// The block index and var table are the two places a corrupt catalog can steer
// the parser outside the file; both must be refused instead of dereferenced.
func TestAssetCatalogIndexGuards(t *testing.T) {
	be := binary.BigEndian
	// Slot 1 (CARHEADER) points a page past the end of the image.
	err := assetCatalogMutate(t, func(img []byte) { be.PutUint32(img[32+4+8:], 0xFFFFFF00) })
	if err == nil || !strings.Contains(err.Error(), "runs past the file") {
		t.Fatalf("out-of-file block offset = %v", err)
	}
	// The index length no longer covers the declared slot count.
	err = assetCatalogMutate(t, func(img []byte) { be.PutUint32(img[20:], 12) })
	if err == nil || !strings.Contains(err.Error(), "index length") {
		t.Fatalf("short index = %v", err)
	}
	// A var table without RENDITIONS leaves nothing to walk.
	err = assetCatalogMutate(t, func(img []byte) {
		i := strings.Index(string(img), "RENDITIONS")
		if i < 0 {
			t.Fatal("fixture lost its RENDITIONS var")
		}
		copy(img[i:], "RENDITIONX")
	})
	if err == nil || !strings.Contains(err.Error(), "no RENDITIONS tree") {
		t.Fatalf("missing RENDITIONS var = %v", err)
	}
}

// A bare port is documented shorthand for the debug endpoint; webTarget's
// process-name test used to swallow it. Keep the expansion pinned.
func TestWebmcpTargetBarePort(t *testing.T) {
	cases := map[string]string{
		"9222":           "127.0.0.1:9222",
		"127.0.0.1:9222": "127.0.0.1:9222",
		"":               "",
		"App.asar":       "App.asar",
		"12ab":           "12ab",
	}
	for in, want := range cases {
		if got := webmcpTarget(in); got != want {
			t.Fatalf("webmcpTarget(%q) = %q, want %q", in, got, want)
		}
	}
}
