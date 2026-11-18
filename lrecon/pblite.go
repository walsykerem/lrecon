package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Protobuf-lite wire walker: a tag, then a wire-dependent payload. Wire types
// 0, 1, 2 and 5 are the whole lite subset; groups (3, 4) are never emitted, so
// they are rejected instead of skipped. No schema, no generated code.

var errPBTruncated = errors.New("truncated protobuf varint")

// pbWalk calls fn for every field of one message, in wire order. A nested
// message arrives as its length-delimited body, ready for a second pbWalk.
func pbWalk(buf []byte, fn func(num, wire int, v uint64, b []byte) error) error {
	for pos := 0; pos < len(buf); {
		tag, n := binary.Uvarint(buf[pos:])
		if n <= 0 {
			return fmt.Errorf("tag @%d: %w", pos, errPBTruncated)
		}
		start := pos
		pos += n
		num, wire := int(tag>>3), int(tag&7)
		if num == 0 {
			return fmt.Errorf("field 0 @%d", start)
		}
		var v uint64
		var b []byte
		switch wire {
		case 0:
			v, n = binary.Uvarint(buf[pos:])
			if n <= 0 {
				return fmt.Errorf("varint field %d @%d: %w", num, pos, errPBTruncated)
			}
			pos += n
		case 1:
			if len(buf)-pos < 8 {
				return fmt.Errorf("fixed64 field %d @%d: %w", num, pos, errPBTruncated)
			}
			v = binary.LittleEndian.Uint64(buf[pos:])
			pos += 8
		case 2:
			l, m := binary.Uvarint(buf[pos:])
			if m <= 0 {
				return fmt.Errorf("length field %d @%d: %w", num, pos, errPBTruncated)
			}
			pos += m
			if l > uint64(len(buf)-pos) {
				return fmt.Errorf("length field %d @%d: %d bytes past end", num, pos-m, l)
			}
			b = buf[pos : pos+int(l)]
			pos += int(l)
		case 5:
			if len(buf)-pos < 4 {
				return fmt.Errorf("fixed32 field %d @%d: %w", num, pos, errPBTruncated)
			}
			v = uint64(binary.LittleEndian.Uint32(buf[pos:]))
			pos += 4
		default:
			return fmt.Errorf("wire type %d field %d @%d", wire, num, start)
		}
		if err := fn(num, wire, v, b); err != nil {
			return err
		}
	}
	return nil
}

// pbInts decodes a packed repeated int32 body. A negative value arrives as its
// 10-byte two's-complement varint, which int32() truncates back.
func pbInts(b []byte) ([]int32, error) {
	out := make([]int32, 0, len(b)/2+1)
	for len(b) > 0 {
		v, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, errPBTruncated
		}
		out = append(out, int32(v))
		b = b[n:]
	}
	return out, nil
}
