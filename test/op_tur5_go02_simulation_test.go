package main

// Tur5 lane 02: simulation tests for the helpers the probe-level suites only
// reach indirectly. Every case drives real parser state (ar bytes, a dex image,
// a synthetic APK, a stale lock owner) so a regression in the helper fails here.

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// ---------- rlib.go: ar member walk, GNU long names, crate claims ----------

func TestTur5Go02RlibDirectHelpers(t *testing.T) {
	t.Run("hash", func(t *testing.T) {
		for _, c := range []struct {
			s    string
			want bool
		}{
			{"0123456789abcdef", true},
			{"", false},
			{"0123456789abcdeg", false},
			{"0123456789ABCDEF", false},
			{"abc-123", false},
		} {
			if got := rlibHash(c.s); got != c.want {
				t.Errorf("rlibHash(%q) = %v, want %v", c.s, got, c.want)
			}
		}
	})

	t.Run("filecrate", func(t *testing.T) {
		if crate, ok := rlibFileCrate("libfoo-0123456789abcdef.rlib"); !ok || crate != "foo" {
			t.Errorf("hashed name = %q,%v, want foo,true", crate, ok)
		}
		if _, ok := rlibFileCrate("libfoo.rlib"); ok {
			t.Error("name without a hash must not claim a crate")
		}
	})

	const cguName = "libfoo.foo.0123456789abcdef-cgu.0.rcgu.o"
	for _, bsd := range []bool{false, true} {
		name := "GNU"
		if bsd {
			name = "BSD"
		}
		t.Run(name, func(t *testing.T) {
			version := "rustc 1.92.0 (abc123 2026-01-01)"
			path := rlibWrite(t, "libfoo-0123456789abcdef.rlib", bsd, []rlibEntry{
				{name: "lib.rmeta", body: rlibBlob(10, 16, version)},
				{name: cguName, body: rlibCgu("foo")},
			})
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			st, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}
			members, err := rlibMembers(f, st.Size())
			if err != nil {
				t.Fatalf("rlibMembers: %v", err)
			}
			if len(members) != 2 {
				t.Fatalf("members = %+v, want 2", members)
			}
			if members[0].name != "lib.rmeta" || members[1].name != cguName {
				t.Fatalf("resolved names = %q, %q", members[0].name, members[1].name)
			}
			// GNU prepends a "//" table, BSD inlines the name in the first
			// payload; both shift the payload off past the bare 8+60 header.
			if members[0].off <= 8+60 || members[0].size != int64(len(rlibBlob(10, 16, version))) {
				t.Errorf("first member = %+v", members[0])
			}
			crate, off, ok := rlibCguCrate(members)
			if !ok || crate != "foo" || off != members[1].off {
				t.Errorf("rlibCguCrate = %q,%d,%v", crate, off, ok)
			}
		})
	}

	t.Run("longname", func(t *testing.T) {
		table := []byte("libvery_long_crate_name/\nnext/\n")
		if got := rlibLongName(table, "0"); got != "libvery_long_crate_name" {
			t.Errorf("long name = %q", got)
		}
		if got := rlibLongName(table, "25"); got != "next" {
			t.Errorf("second long name = %q", got)
		}
		for _, off := range []string{"x", "-1", "999"} {
			if got := rlibLongName(table, off); got != "" {
				t.Errorf("rlibLongName(%q) = %q, want empty", off, got)
			}
		}
	})
}

// ---------- op_project_android_application_graph.go: real APK graph ----------

func TestTur5Go02ProjectAndroidGraphSimulation(t *testing.T) {
	apk := writeZip(t, "app.apk", []zipEntry{
		{"AndroidManifest.xml", axmlComponentsFixture(true)},
		{"classes.dex", dexHappy().build()},
	})

	t.Run("components", func(t *testing.T) {
		got := androidGraphComponents(apk)
		want := []string{
			"activity com.example.app.MainActivity",
			"service com.example.app.SyncService",
			"receiver com.example.app.BootReceiver",
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("components = %v, want %v", got, want)
		}
	})

	t.Run("dexnodes", func(t *testing.T) {
		r, err := dexOpen(dexHappy().build(), &Digest{})
		if err != nil {
			t.Fatal(err)
		}
		nodes := dexGraphNodes(r)
		if len(nodes) != 2 {
			t.Fatalf("dexGraphNodes = %+v, want 2 classes", nodes)
		}
		if nodes[0].Name != "Lcom/example/Foo;" || nodes[0].Super != "Ljava/lang/Object;" {
			t.Errorf("node 0 = %+v", nodes[0])
		}
		if !reflect.DeepEqual(nodes[0].Methods, []string{"<init>", "run"}) {
			t.Errorf("Foo methods = %v", nodes[0].Methods)
		}
		if nodes[1].Name != "Lcom/example/Bar;" {
			t.Errorf("node 1 = %+v", nodes[1])
		}
	})

	t.Run("graph", func(t *testing.T) {
		out, err := runProjectAndroidGraph(apk)
		if err != nil {
			t.Fatal(err)
		}
		m := out.(map[string]any)
		if m["package"] != "com.example.app" {
			t.Errorf("package = %v", m["package"])
		}
		if m["node_count"] != 6 || m["edge_count"] != 7 {
			t.Errorf("graph counts = %v/%v, want 6/7", m["node_count"], m["edge_count"])
		}
		if m["file"] != apk {
			t.Errorf("file = %v, want %q", m["file"], apk)
		}
		kinds := map[string]bool{}
		for _, n := range m["nodes"].([]metaNode) {
			kinds[n.Kind] = true
		}
		for _, k := range []string{"package", "activity", "service", "receiver", "class"} {
			if !kinds[k] {
				t.Errorf("missing node kind %q in %v", k, kinds)
			}
		}
		edgeKinds := map[string]int{}
		for _, e := range m["edges"].([]metaEdge) {
			edgeKinds[e.Kind]++
		}
		if edgeKinds["declares"] != 3 || edgeKinds["contains"] != 2 || edgeKinds["extends"] != 2 {
			t.Errorf("edge kinds = %v", edgeKinds)
		}
	})

	t.Run("no-manifest-refused", func(t *testing.T) {
		empty := writeZip(t, "empty.apk", []zipEntry{{"readme.txt", []byte("x")}})
		_, err := runProjectAndroidGraph(empty)
		if err == nil || !strings.Contains(err.Error(), "has no decoded AndroidManifest") {
			t.Errorf("empty APK error = %v", err)
		}
	})
}

// ---------- asar.go: scoped top-level modules ----------

func TestTur5Go02AsarScopedModules(t *testing.T) {
	pkg := func() *asarNode { return &asarNode{Files: map[string]*asarNode{"package.json": {}}} }
	root := &asarNode{Files: map[string]*asarNode{
		"node_modules": {Files: map[string]*asarNode{
			"plain": pkg(),
			"@scope": {Files: map[string]*asarNode{
				"a":      pkg(),
				"b":      pkg(),
				"broken": {Files: map[string]*asarNode{}},
			}},
			"not-a-module": {Files: map[string]*asarNode{}},
		}},
	}}
	if got := topLevelModules(root); got != 3 {
		t.Errorf("topLevelModules = %d, want 3 (plain + 2 scoped)", got)
	}
	if got := topLevelModules(&asarNode{}); got != 0 {
		t.Errorf("empty root modules = %d", got)
	}
}

// ---------- op_native_cache.go: cache identity + stale lock takeover ----------

func TestTur5Go02GhidraCacheIdentityAndStaleLock(t *testing.T) {
	t.Run("scriptdigest", func(t *testing.T) {
		a := ghidraScriptDigest("script A")
		if len(a) != 16 || a != ghidraScriptDigest("script A") {
			t.Errorf("script digest not stable/length: %q", a)
		}
		if a == ghidraScriptDigest("script B") {
			t.Error("changed script kept the same digest")
		}
	})

	t.Run("stalelock", func(t *testing.T) {
		now := time.Now()
		// Our own pid is never stale, however old the timestamp: another
		// goroutine in this process may hold the lock.
		if reason, stale := ghidraStaleLock(ghidraLockOwner{PID: os.Getpid(), Since: now.Add(-time.Hour)}, now); stale {
			t.Errorf("own pid taken over: %q", reason)
		}
		if reason, stale := ghidraStaleLock(ghidraLockOwner{PID: 999999, Since: now}, now); !stale || !strings.Contains(reason, "is gone") {
			t.Errorf("dead pid = %q,%v, want is gone", reason, stale)
		}
		// A live holder (init) over twice its budget is hung and taken over.
		hung := ghidraLockOwner{PID: 1, Since: now.Add(-time.Hour), Budget: time.Second}
		if reason, stale := ghidraStaleLock(hung, now); !stale || !strings.Contains(reason, "over twice") {
			t.Errorf("hung holder = %q,%v, want over twice", reason, stale)
		}
		live := ghidraLockOwner{PID: 1, Since: now, Budget: time.Minute}
		if reason, stale := ghidraStaleLock(live, now); stale {
			t.Errorf("live holder taken over: %q", reason)
		}
	})
}
