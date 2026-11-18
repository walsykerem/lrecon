package main

import (
	"fmt"
	"strings"
)

// metaAppFields are the digest paths that describe an application version
// rather than a build detail. A change here is a release-level change.
var metaAppFields = map[string]bool{
	"kind": true, "format": true, "minos": true, "uuid": true, "soname": true,
	"build_id": true, "mobile_package": true, "mobile_sdk": true,
	"mobile_permissions": true, "plist_keys": true, "asar_version": true,
	"asar_product": true, "asar_main": true, "electron": true,
	"flutter_hash": true, "deps": true, "capabilities": true, "imports": true,
	"dylibs": true, "exports": true, "slices": true, "slice_info": true,
}

func metaIsAppField(path string) bool {
	base, _, _ := strings.Cut(path, ".")
	return metaAppFields[base]
}

func init() {
	registerOp(op{
		name:  "compare_application_versions",
		route: "L",
		needs: true,
		desc:  "Compare two application builds (job {\"old\",\"new\"}): package/version/sdk/permissions/deps/imports changes only, with a per-field before/after and an identity verdict.",
		run:   runCompareApplicationVersions,
	})
}

func runCompareApplicationVersions(path string) (any, error) {
	job, err := metaLoadJob(path)
	if err != nil {
		return nil, err
	}
	aSide, a, bSide, b, err := metaComparePair(job)
	if err != nil {
		return nil, fmt.Errorf("compare_application_versions: %w", err)
	}
	changes := []metaChange{}
	identity := []string{}
	for _, c := range metaChanges(a, b) {
		if !metaIsAppField(c.Path) {
			continue
		}
		changes = append(changes, c)
		base, _, _ := strings.Cut(c.Path, ".")
		if base == "mobile_package" || base == "asar_version" || base == "asar_product" || base == "mobile_sdk" {
			identity = append(identity, c.Path)
		}
	}
	res := map[string]any{
		"old":              aSide,
		"new":              bSide,
		"changes":          changes,
		"count":            len(changes),
		"identity_changed": identity,
		"same_release":     len(identity) == 0 && aSide.SHA256 == bSide.SHA256,
	}
	if aSide.SHA256 == bSide.SHA256 {
		res["verdict"] = "same bytes"
	} else if len(identity) == 0 {
		res["verdict"] = "same application identity, different build"
	} else {
		res["verdict"] = "application identity changed: " + strings.Join(identity, ", ")
	}
	return res, nil
}
