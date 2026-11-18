package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// Java .class files share the 0xcafebabe magic with the universal Mach-O
// header. detect.go keeps a plausible fat binary and the class reader only
// claims what it can prove: a class-file version where fat Mach-O puts
// nfat_arch, a live constant pool, and no CPU type where a slice belongs.
const (
	javaMagic     = 0xcafebabe
	javaMinMajor  = 45 // JDK 1.1; anything below is not a class file version
	javaMaxRead   = 16 << 20
	javaTagUTF8   = 1
	javaTagClass  = 7
	javaACCModule = 0x8000
)

func init() {
	reasonRegistry["java"] = reasonSet("java-constant-pool-invalid", "java-truncated", "module-info", "no-disassembler")
	register(reader{
		format: "java",
		reasons: []string{
			"java-constant-pool-invalid",
			"java-truncated",
			"module-info",
			"no-disassembler",
		},
		match:   javaMatch,
		inspect: inspectJava,
	})
}

// javaMatch takes CAFEBABE plus a class-file version and a non-empty constant
// pool, but never a real universal binary: fatMachOOK/fatMachOTruncated own
// that shape, so detection order cannot turn a Mach-O into a class.
func javaMatch(head []byte, size int64) bool {
	if len(head) < 10 || binary.BigEndian.Uint32(head) != javaMagic {
		return false
	}
	if fatMachOOK(head, size) || fatMachOTruncated(head, size) {
		return false
	}
	major := int(binary.BigEndian.Uint16(head[6:8]))
	return major >= javaMinMajor && binary.BigEndian.Uint16(head[8:10]) > 0
}

// javaVersion maps major to the release it belongs to: 45..48 are 1.1..1.4,
// 49 is Java 5 and every later one is major-44 (JDK 21 is 65).
func javaVersion(major int) string {
	if major < 49 {
		return fmt.Sprintf("jdk 1.%d", major-44)
	}
	return fmt.Sprintf("java %d", major-44)
}

// inspectJava walks the constant pool up to this_class, then stops. Code
// attributes, bytecode and annotations are named as skipped, not guessed at.
func inspectJava(path string, d *Digest) {
	b, err := readJavaFile(path)
	if err != nil {
		d.Notes = append(d.Notes, "java: "+err.Error())
		d.skip("java-truncated", err.Error())
		d.unparsed()
		return
	}
	d.scanned(int64(len(b)))
	if len(b) < 10 {
		d.skip("java-truncated", fmt.Sprintf("%d bytes, header is 10", len(b)))
		d.unparsed()
		return
	}
	major := int(binary.BigEndian.Uint16(b[6:8]))
	d.Toolchain = javaVersion(major)
	cpCount := int(binary.BigEndian.Uint16(b[8:10]))
	names, classes, off, ok := javaConstantPool(b, cpCount)
	if !ok {
		// The header named a class version, so the toolchain stays: dispatch
		// reverts an unparsed kind only when the reader stamped nothing, and a
		// refused constant pool is a java file, not junk.
		d.skip("java-constant-pool-invalid", fmt.Sprintf("cp_count=%d walk left %d bytes at %#x", cpCount, len(b), off))
		d.unparsed()
		return
	}
	if off+4 > len(b) {
		d.skip("java-truncated", fmt.Sprintf("class header cut at %#x of %d", off, len(b)))
		d.unparsed()
		return
	}
	flags := binary.BigEndian.Uint16(b[off:])
	thisIdx := int(binary.BigEndian.Uint16(b[off+2:]))
	name := ""
	if ni, ok := classes[thisIdx]; ok {
		name = names[ni]
	}
	if name == "" {
		d.skip("java-constant-pool-invalid", fmt.Sprintf("this_class #%d does not resolve to a Utf8 name", thisIdx))
		d.unparsed()
		return
	}
	if name == "module-info" || flags&javaACCModule != 0 {
		d.skip("module-info", "module descriptor, no class body to read")
		d.unparsed()
		return
	}
	d.Format = "class"
	d.Names = name
	d.claim(name, "this_class", int64(off+2))
	d.claim(d.Toolchain, "minor-major", 4)
	d.parsed()
	d.skip("no-disassembler", "Code attributes and bytecode unread")
}

// javaConstantPool returns the Utf8 entries by index and the CONSTANT_Class
// name indexes, plus the offset just past the pool. A walk that runs off the
// buffer or hits an unknown tag means the file is not a class after all.
func javaConstantPool(b []byte, cpCount int) (names map[int]string, classes map[int]int, end int, ok bool) {
	names, classes = map[int]string{}, map[int]int{}
	off := 10
	for i := 1; i < cpCount; i++ {
		if off+1 > len(b) {
			return nil, nil, off, false
		}
		tag := b[off]
		off++
		switch tag {
		case javaTagUTF8:
			if off+2 > len(b) {
				return nil, nil, off, false
			}
			n := int(binary.BigEndian.Uint16(b[off:]))
			off += 2
			if off+n > len(b) {
				return nil, nil, off, false
			}
			names[i] = string(b[off : off+n])
			off += n
			continue
		case javaTagClass:
			if off+2 > len(b) {
				return nil, nil, off, false
			}
			classes[i] = int(binary.BigEndian.Uint16(b[off:]))
			off += 2
			continue
		case 3, 4, 9, 10, 11, 12, 17, 18: // int, float, refs, NameAndType, dynamic
			off += 4
		case 5, 6: // long and double occupy two pool slots
			off += 8
			i++
		case 8, 16, 19, 20: // String, MethodType, Module, Package
			off += 2
		case 15: // MethodHandle
			off += 3
		default:
			return nil, nil, off, false
		}
	}
	if off > len(b) {
		return nil, nil, off, false
	}
	return names, classes, off, true
}

func readJavaFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Size the buffer from the file: the 16 MiB cap is a ceiling, not a cost to
	// pay per .class file, and a growing file is still cut at the cap.
	n := int64(javaMaxRead)
	if st, err := f.Stat(); err == nil && st.Size() < n {
		n = st.Size()
	}
	buf := make([]byte, n)
	read, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	return buf[:read], nil
}
