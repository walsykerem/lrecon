package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func init() {
	registerOp(op{
		name:  "project_apple_application_graph",
		route: "L",
		needs: true,
		desc:  "Project a macOS/iOS application into a graph: bundle node, its declared Info.plist keys, the app.asar summary and the unpacked-native count, with declares/contains edges.",
		run:   runProjectAppleGraph,
	})
}

func runProjectAppleGraph(path string) (any, error) {
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
	// A .app is a directory; the keys live in Contents/Info.plist (macOS) or
	// Info.plist (iOS). Digest that file as well instead of refusing the bundle
	// because the directory digest has no plist keys of its own.
	if len(d.PlistKeys) == 0 {
		if plist := appleBundlePlist(target); plist != "" {
			if pd, perr := loadDigest(plist); perr == nil {
				d.PlistKeys = pd.PlistKeys
				if d.MinOS == "" {
					d.MinOS = pd.MinOS
				}
			}
		}
	}
	if len(d.PlistKeys) == 0 && d.AsarFiles == 0 && d.UnpackedNode == 0 {
		return nil, fmt.Errorf("project_apple_application_graph: %s has no Info.plist keys, asar files or unpacked node (kind %q)", target, d.Kind)
	}
	bundle := metaNode{Kind: "bundle", Name: filepath.Base(target), Detail: fmt.Sprintf("minos=%s kind=%s", d.MinOS, d.Kind)}
	nodes := []metaNode{bundle}
	var edges []metaEdge
	for _, k := range d.PlistKeys {
		nodes = append(nodes, metaNode{Kind: "plist-key", Name: k})
		edges = append(edges, metaEdge{From: bundle.Name, To: k, Kind: "declares"})
	}
	if d.AsarFiles > 0 {
		asar := metaNode{Kind: "asar", Name: "app.asar", Detail: fmt.Sprintf("files=%d electron=%s version=%s product=%s", d.AsarFiles, d.ElectronVer, d.AsarVersion, d.AsarProduct)}
		nodes = append(nodes, asar)
		edges = append(edges, metaEdge{From: bundle.Name, To: asar.Name, Kind: "contains"})
		if d.AsarMain != "" {
			nodes = append(nodes, metaNode{Kind: "entrypoint", Name: d.AsarMain})
			edges = append(edges, metaEdge{From: asar.Name, To: d.AsarMain, Kind: "contains"})
		}
	}
	if d.UnpackedNode > 0 {
		nodes = append(nodes, metaNode{Kind: "native", Name: "asar.unpacked", Detail: fmt.Sprintf("files=%d", d.UnpackedNode)})
		// asar.unpacked is a sibling of app.asar, but it can outlive it (the
		// archive deleted, the addon directory left behind). An edge from a node
		// that is not in the graph would dangle, so it hangs off the bundle then.
		from := bundle.Name
		if d.AsarFiles > 0 {
			from = "app.asar"
		}
		edges = append(edges, metaEdge{From: from, To: "asar.unpacked", Kind: "contains"})
	}
	if d.FlutterHash != "" {
		nodes = append(nodes, metaNode{Kind: "flutter", Name: "libapp.so", Detail: "snapshot=" + d.FlutterHash})
		edges = append(edges, metaEdge{From: bundle.Name, To: "libapp.so", Kind: "contains"})
	}
	res := metaGraphResult(nodes, edges)
	res["file"] = target
	res["kind"] = d.Kind
	return res, nil
}

// appleBundlePlist returns the Info.plist inside an application directory, or ""
// when the target is a file or carries no readable plist.
func appleBundlePlist(target string) string {
	st, err := os.Stat(target)
	if err != nil || !st.IsDir() {
		return ""
	}
	for _, rel := range []string{"Contents/Info.plist", "Info.plist"} {
		p := filepath.Join(target, rel)
		if f, err := os.Stat(p); err == nil && f.Mode().IsRegular() {
			return p
		}
	}
	return ""
}
