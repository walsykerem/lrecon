package main

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

// An APK that requests nothing must still marshal "permissions": null rather
// than refusing or inventing an empty list: the field is the op's wire
// contract and existing consumers read it as a null-or-list.
func TestInspectAndroidPackageNoPermissions(t *testing.T) {
	strs := []string{"manifest", "package", "name", "uses-sdk",
		"minSdkVersion", "targetSdkVersion", "com.example.app"}
	idx := map[string]uint32{}
	for i, s := range strs {
		idx[s] = uint32(i)
	}
	var body []byte
	body = append(body, axmlPool(strs, true)...)
	body = append(body, axmlTag(idx, "manifest", []testAttr{{name: "package", str: "com.example.app", kind: 0x03}})...)
	body = append(body, axmlTag(idx, "uses-sdk", []testAttr{
		{name: "minSdkVersion", kind: 0x10, num: 21},
		{name: "targetSdkVersion", kind: 0x10, num: 33},
	})...)
	head := make([]byte, 8)
	binary.LittleEndian.PutUint16(head[0:], 0x0003)
	binary.LittleEndian.PutUint16(head[2:], 8)
	binary.LittleEndian.PutUint32(head[4:], uint32(8+len(body)))

	p := writeZip(t, "noperm.apk", []zipEntry{
		{"AndroidManifest.xml", append(head, body...)},
		{"classes.dex", dexFile()},
	})
	v, err := runOp("inspect_android_package", p)
	if err != nil {
		t.Fatalf("inspect_android_package: %v", err)
	}
	js, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), `"permissions":null`) {
		t.Fatalf("permissionless APK marshals %s, want \"permissions\":null", js)
	}
}
