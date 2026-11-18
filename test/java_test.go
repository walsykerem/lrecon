package main

import (
	"encoding/binary"
	"testing"
)

// classBytes builds a minimal but walkable class file: two Utf8 names and the
// two CONSTANT_Class entries they back, then an empty class body.
func classBytes(name string, major int, flags uint16) []byte {
	b := []byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00}
	u16 := func(v uint16) { b = binary.BigEndian.AppendUint16(b, v) }
	u16(uint16(major)) // major version
	u16(5)             // constant_pool_count
	b = append(b, javaTagUTF8)
	u16(uint16(len(name)))
	b = append(b, name...)
	b = append(b, javaTagClass)
	u16(1)
	b = append(b, javaTagUTF8)
	u16(uint16(len("java/lang/Object")))
	b = append(b, "java/lang/Object"...)
	b = append(b, javaTagClass)
	u16(3)
	u16(flags) // access_flags
	u16(2)     // this_class
	u16(4)     // super_class
	u16(0)     // interfaces_count
	u16(0)     // fields_count
	u16(0)     // methods_count
	u16(0)     // attributes_count
	return b
}

func skippedReasons(d Digest) map[string]bool {
	m := map[string]bool{}
	for _, s := range d.Skipped {
		m[s.Reason] = true
	}
	return m
}

func TestJavaClassProbe(t *testing.T) {
	d, err := Probe(writeTemp(t, "Main.class", classBytes("com/example/Main", 65, 0x0021)))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "java" {
		t.Fatalf("kind = %q, want java", d.Kind)
	}
	if d.Format != "class" {
		t.Fatalf("format = %q, want class", d.Format)
	}
	if d.Toolchain != "java 21" {
		t.Fatalf("toolchain = %q, want java 21 (major 65)", d.Toolchain)
	}
	if d.Names != "com/example/Main" {
		t.Fatalf("names = %q, want this_class name", d.Names)
	}
	if !skippedReasons(d)["no-disassembler"] {
		t.Fatalf("no no-disassembler skip: %+v", d.Skipped)
	}
}

func TestJavaVersionTable(t *testing.T) {
	cases := []struct {
		major int
		want  string
	}{
		{45, "jdk 1.1"},
		{48, "jdk 1.4"},
		{49, "java 5"},
		{52, "java 8"},
		{61, "java 17"},
		{65, "java 21"},
	}
	for _, c := range cases {
		if got := javaVersion(c.major); got != c.want {
			t.Errorf("javaVersion(%d) = %q, want %q", c.major, got, c.want)
		}
	}
}

func TestJavaModuleInfoRefused(t *testing.T) {
	for _, c := range []struct{ name, why string }{
		{"module-info", "descriptor"},
		{"app/Thing", "ACC_MODULE"},
	} {
		flags := uint16(0x0021)
		if c.why == "ACC_MODULE" {
			flags = javaACCModule
		}
		d, err := Probe(writeTemp(t, "module-info.class", classBytes(c.name, 65, flags)))
		if err != nil {
			t.Fatalf("%s: Probe: %v", c.why, err)
		}
		if d.Kind != "java" {
			t.Fatalf("%s: kind = %q, want java", c.why, d.Kind)
		}
		if !skippedReasons(d)["module-info"] {
			t.Fatalf("%s: no module-info skip: %+v", c.why, d.Skipped)
		}
		if d.Names != "" {
			t.Fatalf("%s: refused file still named a class: %q", c.why, d.Names)
		}
	}
}

func TestJavaConstantPoolInvalid(t *testing.T) {
	// magic and version are right, but the pool declares more entries than the
	// file carries: match claims it, the walk must refuse it.
	b := classBytes("Broken", 65, 0x0021)
	binary.BigEndian.PutUint16(b[8:10], 500)
	d, err := Probe(writeTemp(t, "Broken.class", b))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "java" {
		t.Fatalf("kind = %q, want java", d.Kind)
	}
	if !skippedReasons(d)["java-constant-pool-invalid"] {
		t.Fatalf("no java-constant-pool-invalid skip: %+v", d.Skipped)
	}
}

// TestJavaFatMachOStaysMacho: the universal binary keeps the magic it shares
// with a class file, and the java reader must not claim its header shape.
func TestJavaFatMachOStaysMacho(t *testing.T) {
	fat := make([]byte, 4096)
	binary.BigEndian.PutUint32(fat[0:4], 0xcafebabe)
	binary.BigEndian.PutUint32(fat[4:8], 2)           // nfat_arch
	binary.BigEndian.PutUint32(fat[8:12], 0x0100000c) // arm64
	binary.BigEndian.PutUint32(fat[16:20], 48)        // first slice offset
	binary.BigEndian.PutUint32(fat[20:24], 1024)      // first slice size
	if javaMatch(fat[:512], int64(len(fat))) {
		t.Fatal("java reader claimed a universal binary header")
	}
	d, err := Probe(writeTemp(t, "fat.bin", fat))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "macho" || d.Format != "fat" {
		t.Fatalf("kind/format = %q/%q, want macho/fat", d.Kind, d.Format)
	}

	class := classBytes("com/example/Main", 65, 0x0021)
	if !javaMatch(class, int64(len(class))) {
		t.Fatal("java reader missed a valid class header")
	}
}
