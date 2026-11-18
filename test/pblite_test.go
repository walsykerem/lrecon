package main

import (
	"encoding/binary"
	"errors"
	"testing"
)

func pbTag(num, wire int) []byte {
	var b []byte
	return binary.AppendUvarint(b, uint64(num<<3|wire))
}

func TestPBWalkFields(t *testing.T) {
	var b []byte
	b = append(b, pbTag(1, 0)...)
	b = binary.AppendUvarint(b, 300)
	b = append(b, pbTag(2, 1)...)
	b = binary.LittleEndian.AppendUint64(b, 0x1122334455667788)
	b = append(b, pbTag(3, 2)...)
	b = binary.AppendUvarint(b, 2)
	b = append(b, 'h', 'i')
	b = append(b, pbTag(4, 5)...)
	b = binary.LittleEndian.AppendUint32(b, 0x0a0b0c0d)

	type seen struct {
		num, wire int
		v         uint64
		body      string
	}
	var got []seen
	err := pbWalk(b, func(num, wire int, v uint64, body []byte) error {
		got = append(got, seen{num, wire, v, string(body)})
		return nil
	})
	if err != nil {
		t.Fatalf("pbWalk: %v", err)
	}
	want := []seen{
		{1, 0, 300, ""},
		{2, 1, 0x1122334455667788, ""},
		{3, 2, 0, "hi"},
		{4, 5, 0x0a0b0c0d, ""},
	}
	if len(got) != len(want) {
		t.Fatalf("fields %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("field %d %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestPBWalkRefusals(t *testing.T) {
	nested := append(pbTag(1, 2), 5) // claims 5 bytes, one present
	cases := map[string]struct {
		buf  []byte
		want error
	}{
		"cut tag":       {[]byte{0x80}, errPBTruncated},
		"field zero":    {[]byte{0x00, 0x01}, nil},
		"group start":   {append(pbTag(1, 3), pbTag(1, 0)...), nil},
		"group end":     {append(pbTag(1, 4), pbTag(1, 0)...), nil},
		"cut varint":    {append(pbTag(1, 0), 0x80), errPBTruncated},
		"cut fixed64":   {pbTag(1, 1), errPBTruncated},
		"cut fixed32":   {append(pbTag(1, 5), 1, 2), errPBTruncated},
		"past end":      {nested, nil},
		"length varint": {append(pbTag(1, 2), 0x80), errPBTruncated},
	}
	for name, c := range cases {
		err := pbWalk(c.buf, func(int, int, uint64, []byte) error { return nil })
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if c.want != nil && !errors.Is(err, c.want) {
			t.Fatalf("%s: %v, want %v", name, err, c.want)
		}
	}
}

func TestPBInts(t *testing.T) {
	var packed []byte
	for _, v := range []int32{1, 2, 300, -1} {
		packed = binary.AppendUvarint(packed, uint64(int64(v)))
	}
	got, err := pbInts(packed)
	if err != nil {
		t.Fatalf("pbInts: %v", err)
	}
	want := []int32{1, 2, 300, -1}
	if len(got) != len(want) {
		t.Fatalf("ints %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("int %d %d, want %d", i, got[i], want[i])
		}
	}
	if _, err := pbInts([]byte{0x80}); !errors.Is(err, errPBTruncated) {
		t.Fatalf("cut packed varint: %v", err)
	}
}
