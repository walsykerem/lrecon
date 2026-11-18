package main

import (
	"archive/zip"
	"fmt"
	"strings"
)

// dexClassLines parses the "dex: class ..." notes the mobile reader records.
func dexClassLines(d Digest) []metaNode {
	var out []metaNode
	for _, n := range d.Notes {
		line := strings.TrimSpace(n)
		if !strings.HasPrefix(line, "dex: class ") {
			continue
		}
		rest := strings.TrimPrefix(line, "dex: class ")
		node := metaNode{Kind: "class"}
		if i := strings.Index(rest, " super "); i >= 0 {
			node.Name = rest[:i]
			rest = rest[i+len(" super "):]
		} else {
			node.Name = rest
			rest = ""
		}
		if before, after, ok := strings.Cut(rest, " methods "); ok {
			node.Super = before
			methods := strings.TrimPrefix(after, "methods ")
			if j := strings.Index(methods, ":"); j >= 0 {
				methods = methods[:j]
			}
			for m := range strings.SplitSeq(methods, ",") {
				if m = strings.TrimSpace(m); m != "" {
					node.Methods = append(node.Methods, m)
				}
			}
		} else {
			node.Super = rest
		}
		out = append(out, node)
	}
	return out
}

func init() {
	registerOp(op{
		name:  "project_android_application_graph",
		route: "L",
		needs: true,
		desc:  "Project an APK into a graph: package -> declared components/permissions -> dex classes, with extends and declares edges taken from the manifest and dex class definitions.",
		run:   runProjectAndroidGraph,
	})
}

func runProjectAndroidGraph(path string) (any, error) {
	job, err := metaLoadJob(path)
	if err != nil {
		return nil, err
	}
	target := job.File
	if target == "" {
		target = path
	}
	d, err := loadDigest(target)
	if err != nil {
		return nil, err
	}
	if d.MobilePkg == "" && d.MobileSDK == "" && len(d.MobilePerms) == 0 {
		return nil, fmt.Errorf("project_android_application_graph: %s has no decoded AndroidManifest (kind %q)", target, d.Kind)
	}
	pkg := metaNode{Kind: "package", Name: d.MobilePkg, Detail: "min_sdk=" + d.MobileSDK}
	var nodes []metaNode
	var edges []metaEdge
	nodes = append(nodes, pkg)
	for _, p := range d.MobilePerms {
		nodes = append(nodes, metaNode{Kind: "permission", Name: p})
		edges = append(edges, metaEdge{From: pkg.Name, To: p, Kind: "declares"})
	}
	for _, comp := range androidGraphComponents(target) {
		kind, name, ok := strings.Cut(comp, " ")
		if !ok || name == "" {
			continue
		}
		if strings.HasPrefix(name, ".") && d.MobilePkg != "" {
			name = d.MobilePkg + name
		}
		nodes = append(nodes, metaNode{Kind: kind, Name: name})
		edges = append(edges, metaEdge{From: pkg.Name, To: name, Kind: "declares"})
	}
	for _, c := range androidGraphClasses(target, d) {
		nodes = append(nodes, c)
		edges = append(edges, metaEdge{From: pkg.Name, To: c.Name, Kind: "contains"})
		if c.Super != "" {
			edges = append(edges, metaEdge{From: c.Name, To: c.Super, Kind: "extends"})
		}
	}
	res := metaGraphResult(nodes, edges)
	res["file"], res["package"], res["min_sdk"] = target, d.MobilePkg, d.MobileSDK
	return res, nil
}

// androidGraphClasses returns the classes an APK carries: the dex bytecode is
// decoded here because the mobile digest only records a class line for a raw
// .dex target, so an APK graph would otherwise hold the manifest alone.
func androidGraphClasses(target string, d Digest) []metaNode {
	b, err := dexReadBytes(target)
	if err != nil {
		return dexClassLines(d)
	}
	r, err := dexOpen(b, &Digest{})
	if err != nil {
		return dexClassLines(d)
	}
	nodes := dexGraphNodes(r)
	if len(nodes) == 0 {
		return dexClassLines(d)
	}
	return nodes
}

// dexGraphNodes walks class_defs into graph nodes: descriptor, superclass and
// the method names class_data_item names. Caps match the digest's so a graph
// and a digest describe the same slice of a large dex.
func dexGraphNodes(r dexReader) []metaNode {
	var out []metaNode
	n := int(u32le(r.b, 0x60))
	for i := 0; i < n && len(out) < dexMaxClasses; i++ {
		at := r.clsOff + 32*i
		if !dexIn(r.end, at, 32, 1) {
			break
		}
		desc, ok := r.typeName(u32le(r.b, at))
		if !ok {
			continue
		}
		node := metaNode{Kind: "class", Name: desc}
		if s := u32le(r.b, at+8); s != dexNoIndex {
			if sup, ok := r.typeName(s); ok {
				node.Super = sup
			}
		}
		if _, methods, err := dexClassData(r, int(u32le(r.b, at+24))); err == nil {
			for _, m := range methods {
				if name, ok := r.methodName(m.Idx); ok && len(node.Methods) < dexMaxMethods {
					node.Methods = append(node.Methods, name)
				}
			}
		}
		out = append(out, node)
	}
	return out
}

// androidGraphComponents re-parses the package manifest so the graph carries the
// components the digest keeps only as a deep note: the manifest is one zip entry
// and the AXML/plain readers already know how to lift the names.
func androidGraphComponents(target string) []string {
	zr, err := zip.OpenReader(target)
	if err != nil {
		return nil
	}
	defer zr.Close()
	for _, f := range zr.File {
		if !strings.HasSuffix(strings.ToLower(f.Name), "androidmanifest.xml") {
			continue
		}
		b, ok := readEntry(f, 8<<20)
		if !ok {
			return nil
		}
		var m manifestInfo
		if isBinaryXML(b) {
			m, ok = axmlManifestOf(b)
		} else {
			m, ok = xmlManifestOf(b)
		}
		if !ok {
			return nil
		}
		return m.components
	}
	return nil
}
