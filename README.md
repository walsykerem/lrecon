<p align="center">
  <img src="assets/lrecon.png" alt="lrecon — bytes-only reverse engineering, 330 Go files" width="900">
</p>

<h1 align="center">lrecon</h1>

<p align="center">Reverse engineer a shipped artifact from its bytes. Nothing else.</p>

lrecon is a single Go binary that answers questions about build outputs it did not build: which compiler, which toolchain, which SDK, which packer, which capability is wired in, which symbol points where. Every answer comes from the file itself — headers, tables, sections, trailers, metadata — read by an in-process Go reader. Nothing is uploaded, nothing is executed, nothing is guessed.

Two hundred thirty-five named ops cover the inventory: native binaries and their hardening, Electron/ASAR trees, JavaScript bundles, .NET and IL2CPP assemblies, Go/Rust/Swift build info, Android APK/AAB/DEX, Apple IPA/asset catalogs, WebAssembly, Python `.pyc`, PHP/opcache, capture files, and the fingerprint left by each build system. Eighty more ops cover the runtime layer (adb, CDP, GDB/LLDB, Frida, Ghidra headless) for the questions bytes cannot answer. The remaining core is the machinery all of them share: one format registry, one digest contract, one refusal vocabulary, one budget.

## Download

```sh
npx lrecon@1.0.0 target.apk     # no install, no Go toolchain
npm i -g lrecon                 # or keep it on PATH
```

The npm package carries prebuilt binaries for macOS and Linux (x64, arm64) and Windows x64 and picks the one matching your platform. No runtime, no Go toolchain — `npx` downloads it, runs it, done. Building from source is in [Build](#build).

## Dependencies

The 235 inventory ops need **nothing**: stdlib Go, in-process readers, no cgo, no third-party modules, no network.

The 80 runtime ops shell out to outside tools, and only the op you call needs its tool:

| Tool | Used for | Where it comes from |
|---|---|---|
| Ghidra 12.x `analyzeHeadless` + JDK 21 | the 39 native ops: decompilation, call graphs, traces | `PATH`, else `LRECON_GHIDRA`; one project per binary cached in `~/Library/Caches/lrecon-ghidra` |
| `adb` | Android device and file ops | Android platform-tools on `PATH` |
| `lldb` | debug sessions (`gdb_console`, `gdb_session_status`, `close_gdb_session` run on it; gdb ≥ 11 by hand is the fallback) | LLVM on `PATH` |
| `jadx` | APK class source | on `PATH` |
| `apktool` | APK build, decode, framework cache | on `PATH` |
| a CDP endpoint | browser and Electron captures: a Chrome or Electron already started with `--remote-debugging-port` (default `127.0.0.1:9222`) | you start it; lrecon never spawns a browser |
| Go toolchain | optional: `go tool objdump` backs the symbol-disassembly fallback | any Go install |

A missing tool is not a crash: the op answers `kind: "no_engine"` with the install hint, exit `2`, never a fabricated field. Nothing is vendored and no tool is bundled — lrecon is MIT, each tool keeps its own licence (Ghidra, apktool and jadx are Apache-2.0).

Two things that look like dependencies and are not: **Frida** (the session ops refuse by design — lrecon owns no session and cannot see another process's) and **rizin** (Cutter project listing is a filesystem read, the binary is never run).

## Run

```sh
lrecon target.apk                  # one-screen digest
lrecon --json target.apk           # the same digest as JSON
lrecon --op inspect_go_binary ./svc
lrecon --op analyze_function ./svc  # LRECON_AT / LRECON_NAME
lrecon --list-ops --json           # every op with what it needs
```

Exit codes are the contract: `0` an answer, `1` only `--diff` found differences, `2` no answer. A refusal is still an answer-shaped object:

```json
{"contract_version": 1, "op": "inspect_apk_signature", "target": "x.apk", "error": "…", "kind": "no_engine"}
```

`kind` is one of `io`, `bad_arg`, `no_engine`, `out_of_scope`. Nothing is invented to fill a hole: a reader that cannot prove a field skips it with a reason from a closed vocabulary (`reasonRegistry`, `lrecon/reasons.go`), and a claim needs two witnesses from different derivation classes on disjoint byte ranges (`lrecon/witness.go`).

## Env

`LRECON_AT`, `LRECON_NAME`, `LRECON_FROM`/`LRECON_TO`, `LRECON_ARGS`, `LRECON_QUERY`, `LRECON_PATTERN`, `LRECON_STATE`, `LRECON_GHIDRA`, `LRECON_GHIDRA_TIMEOUT`, `LRECON_GHIDRA_CACHE`, `LRECON_OP_DEADLINE`, `LRECON_ANSWER_CAP_BYTES`. Bad values fall back to defaults; they never fail the run.

## Build

```sh
go build ./... && go test ./...        # core
go build -buildvcs=false -trimpath -ldflags="-s -w" -o lrecon ./lrecon
```

Go stdlib only, no cgo for the cross targets. Version lives in `lrecon/main.go`.

## Layout

| Path | What |
|---|---|
| `lrecon/` | the program: 258 op files + 72 core/engine files, plus testdata fixtures |
| `test/` | cross-file and end-to-end tests that need a built binary |
| `assets/` | README artwork |

## License

MIT — see [LICENSE](LICENSE). © 2026 Kerem Urhan.

## The 330 files

Every `.go` file in `lrecon/`, one line each. Op files first, then the core they run on. `lrecon --op <name> <target>` runs exactly one op; `--list-ops` prints the names.

### Ops — 258 files

1. `lrecon/op_adb_locate.go` — init-time adb discovery: prepends the Android SDK platform-tools dir to PATH when adb is not on PATH
2. `lrecon/op_address_name.go` — address_name op: symbol, function and memory block names at LRECON_AT via headless Ghidra project
3. `lrecon/op_address_to_file_offset.go` — address_to_file_offset op: maps LRECON_AT to its file byte offset through the Ghidra block source map
4. `lrecon/op_analyze_function.go` — analyze_function op: decompiles one Ghidra function picked by LRECON_NAME or LRECON_AT, returns signature
5. `lrecon/op_analyze_javascript_application.go` — analyze_javascript_application op: lexes a JS bundle into imports, exports with arity and literal strings
6. `lrecon/op_analyze_swift_types.go` — analyze_swift_types op: counts __swift5_types/__swift5_proto records, resolves descriptor names per slice
7. `lrecon/op_analyze_web_bundle.go` — analyze_web_bundle op: import/require/export-from edges of one web bundle, deduped into a module-dep map
8. `lrecon/op_annotate_native_function.go` — annotate_native_function op: plate comment with address and text on the containing Ghidra function
9. `lrecon/op_asar_budget.go` — per-op deadline runner and 4 MiB asar lex window shared by the Electron ops, stage-tagged timeouts
10. `lrecon/op_asset_catalog.go` — inspect_asset_catalog: BOMStore index and vars, CARHEADER versions, tmfk keys, rendition pair counts
11. `lrecon/op_batch_decompile.go` — batch_decompile op: decompiles every name/address in LRECON_ARGS, returning lines plus pseudocode each
12. `lrecon/op_binary_overview.go` — binary_overview op: one-screen digest answer of kind, format, slices, toolchain, exports and hardening
13. `lrecon/op_binary_session.go` — binary_session op: opens the analysis session and persists `<state>`/session.json, keeping the cursor per document
14. `lrecon/op_build_call_path.go` — build_call_path op: breadth-first call path from LRECON_FROM to LRECON_TO with depth and visited count
15. `lrecon/op_build_reconstruction_obligation_ledger.go` — build_reconstruction_obligation_ledger op: unresolved symbols with reasons to `<state>`/obligations.json
16. `lrecon/op_capture_adb_screen.go` — capture_adb_screen op: adb screencap PNG whose IHDR size it reports, optionally written to a PNG-only path
17. `lrecon/op_capture_browser_scenario.go` — capture_browser_scenario op: navigates the attached browser to a URL and records that load's request table
18. `lrecon/op_capture_electron_scenario.go` — capture_electron_scenario op: attaches to an already running Electron renderer debug port, records its requests
19. `lrecon/op_capture_native_ui_scenario.go` — capture_native_ui_scenario op: adb input steps, screencap, uiautomator dump until two hashes agree
20. `lrecon/op_capture_process_scenario.go` — capture_process_scenario op: 1 s sample(1) of a live pid parsed into per-thread frames with lib and count
21. `lrecon/op_capture_web_screenshot.go` — capture_web_screenshot op: full-page CDP PNG reporting decoded dimensions, byte size and sha256
22. `lrecon/op_check_deception.go` — check_deception_signals op: canary markers, dangling source maps and shadow state-family strings, static
23. `lrecon/op_check_runtime_evasion.go` — check_runtime_evasion op: static six-family rule pack over the file, reporting first hit offsets
24. `lrecon/op_close_binary.go` — close_binary: session close that removes `<state>`/session.json only when this path owns it
25. `lrecon/op_close_frida_session.go` — close_frida_session: refusal stub, lrecon holds no frida session to detach or unload
26. `lrecon/op_close_gdb_session.go` — close_gdb_session: lldb batch process status shows no debugger session survives between ops
27. `lrecon/op_close_rizin_debug_session.go` — close_rizin_debug_session: refusal stub pointing at the lldb batch equivalent, close_gdb_session
28. `lrecon/op_collect_adb_bugreport.go` — collect_adb_bugreport: bugreportz on the device, pulls the zip back and hashes it into the target path
29. `lrecon/op_comment.go` — comment: sets a ghidra plate comment at a job address and reads it back in the same run
30. `lrecon/op_compare_application_versions.go` — compare_application_versions: release-level diff of package, version, sdk, permissions, deps and imports
31. `lrecon/op_compare_artifacts.go` — compare_artifacts: field-by-field digest diff naming each json path with its before and after value
32. `lrecon/op_compare_bundles.go` — compare_bundles: member-by-member diff of two bundle dirs or apk/aab/ipa/hap archives with sha256
33. `lrecon/op_compare_functions.go` — compare_functions: decompiles LRECON_FROM and LRECON_TO and scores shared pseudocode lines (ghidra)
34. `lrecon/op_compare_javascript_export_shapes.go` — compare_javascript_export_shapes: (name, arity) export tables of two scripts in one dir, added/removed/changed
35. `lrecon/op_compare_managed_members.go` — compare_managed_members: TypeDef/MethodDef surface diff of two .NET assemblies from ECMA-335 tables
36. `lrecon/op_compare_process_captures.go` — compare_process_captures: joins two capture JSONs by symbol and diffs their value arrays element by element
37. `lrecon/op_compare_source_to_bundle.go` — compare_source_to_bundle: matches the asar member list against the source maps the digest found
38. `lrecon/op_compare_wasm_interfaces.go` — compare_wasm_interfaces: diffs import and export section names, sections 2 and 7, of two wasm modules
39. `lrecon/op_compare_web_captures.go` — compare_web_captures: recaptures the request table and diffs method/url/status lines against a saved capture
40. `lrecon/op_compare_web_screenshots.go` — compare_web_screenshots: screenshots the tab, clicks its centre, re-shoots, reports pixel diff and box
41. `lrecon/op_correlate_static_and_runtime.go` — correlate_static_and_runtime: matches .ips usedImages uuids against the probed Mach-O image uuids
42. `lrecon/op_current_address.go` — current_address: resolves the goto_address cursor against the session document function table
43. `lrecon/op_current_document.go` — current_document: session document, project, cursor and known documents from the session record
44. `lrecon/op_current_procedure.go` — current_procedure: function containing the session cursor with its range and offset into it
45. `lrecon/op_cutter_command.go` — cutter_command: refusal stub, Cutter's rizin console is not driven; points at the Ghidra ops
46. `lrecon/op_decode_android_resources.go` — decode_android_resources: parses resources.arsc packages, type/entry tables and resource names from an APK
47. `lrecon/op_decode_interface_builder.go` — decode_interface_builder: reads compiled NIBArchive table counts and real outlet/action connector names
48. `lrecon/op_decode_signal_recording.go` — decode_signal_recording: SigMF sample rate, datatype, count, duration and DFT peak frequency
49. `lrecon/op_decompile_all.go` — decompile_all: decompiles every non-external function within a budget, counts plus samples; IL for .NET
50. `lrecon/op_decompile_jeb_item.go` — decompile_jeb_item: one APK class through jadx --single-class, with the JEB engine note kept
51. `lrecon/op_demangle_swift.go` — demangle_swift: decodes $s/_$s length-prefixed Swift symbols into module.type.function
52. `lrecon/op_discover_webmcp_tools.go` — discover_webmcp_tools: document.modelContext tools from a secure page, labelled native or polyfill
53. `lrecon/op_evaluate_reconstruction_coverage.go` — evaluate_reconstruction_coverage: resolved/unresolved ratio from job lists, state ledger or digest
54. `lrecon/op_execute_rizin_command.go` — execute_rizin_command: refusal stub, no command console; points at the Ghidra static ops
55. `lrecon/op_export_environment_bundle.go` — export_environment_bundle: deterministic tar of manifest.json plus artifact bytes into -o, fixed mtime
56. `lrecon/op_export_evidence_bundle.go` — export_evidence_bundle: self-verifying json bundle with identity, digest fields and sha256 attestation
57. `lrecon/op_export_web_scripts.go` — export_web_scripts: writes every script member of one asar or zip archive into -o DIR, path-safe
58. `lrecon/op_ext_adb_net.go` — adb forward/reverse lists and edits, connect, remount, root, usb attach/detach, keygen, verity, server
59. `lrecon/op_ext_adb_state.go` — adb disconnect, tcpip, emu, wait-for-device, get-state, get-serialno and reboot host subcommands
60. `lrecon/op_ext_apktool.go` — apktool build, framework install/clean/list, publicize, manifest-only, no-res and no-src decodes
61. `lrecon/op_ext_ghidra.go` — ghidra_* items: analyzeHeadless import flags (prescript, processor, cspec, loader, timeout) for a target
62. `lrecon/op_ext_jadx.go` — jadx_* items: gradle export, deobf, call graph, cfg, json output, mappings, single class, plugins
63. `lrecon/op_ext_lldb_memory.go` — lldb register/memory read-write, expression, process launch/attach; the no-process line is an answer
64. `lrecon/op_ext_lldb_misc.go` — lldb disassemble, breakpoints, watchpoint, image lookup, frame vars, backtrace, thread/image/target lists
65. `lrecon/op_extract_artifact.go` — extract_artifact: unpacks zip/apk/aab/ipa/asar into -o DIR behind member-path and size guards
66. `lrecon/op_extract_firmware.go` — extract_firmware: magic-carves squashfs, ubi, cramfs, uimage, dtb, trx and jffs2 from a flash dump
67. `lrecon/op_find_changed_behavior.go` — find_changed_behavior: diff filtered to behaviour-moving fields, each labelled dependency/permission/hardening
68. `lrecon/op_find_xrefs_to_name.go` — find_xrefs_to_name: references to the LRECON_NAME symbol with the calling function (ghidra headless)
69. `lrecon/op_frida_session_status.go` — frida_session_status: refusal stub, no session is owned and another process's cannot be read
70. `lrecon/op_gdb_console.go` — gdb_console: one lldb --batch pass of target list and image list over a binary, no inferior started
71. `lrecon/op_gdb_lldb.go` — lldb engine shared by gdb_console, gdb_session_status and close_gdb_session: batch dialog helper
72. `lrecon/op_gdb_session_status.go` — gdb_session_status: thread ids and stop reason scraped from one lldb batch thread list, empty states why
73. `lrecon/op_get_call_graph.go` — get_call_graph: function and call-edge counts with a bounded edge sample (ghidra headless)
74. `lrecon/op_get_evidence_bundle.go` — get_evidence_bundle: reads an exported bundle back, verifies its attestation, spills oversized bundles
75. `lrecon/op_get_navigation_context.go` — get_navigation_context: session document, cursor, containing procedure and project in one answer
76. `lrecon/op_get_objc_classes.go` — get_objc_classes: walks __objc_classlist through class_t and class_ro_t to list Objective-C class names
77. `lrecon/op_get_objc_protocols.go` — get_objc_protocols: walks __objc_protolist through protocol_t for names and adopted protocols
78. `lrecon/op_ghidra_gate.go` — ghidraGate: refuses route-G ops before local resolution, ordering io error, kind and missing engine
79. `lrecon/op_goto_address.go` — goto_address: validates LRECON_AT inside a file-backed section and makes it the session cursor
80. `lrecon/op_identify_flutter_build.go` — identify_flutter_build: Dart snapshot version hash and kind, or an Android package's Flutter capability
81. `lrecon/op_import_evidence_bundle.go` — import_evidence_bundle: verifies bundle attestation then checks the recorded artifact sha256 on disk
82. `lrecon/op_import_managed_reconstruction.go` — import_managed_reconstruction: writes types.json, methods/`<Type>`.txt and README.md from CLI tables
83. `lrecon/op_inline_comment.go` — inline_comment: sets an end-of-line comment at a job address and reads it back from the project
84. `lrecon/op_inspect_adb_client.go` — inspect_adb_client: adb version and build from the client binary plus the adb devices -l table
85. `lrecon/op_inspect_adb_device.go` — inspect_adb_device: model, sdk, build fingerprint and ro.debuggable via one getprop call
86. `lrecon/op_inspect_adb_display.go` — inspect_adb_display: physical and override screen size and density from wm size and wm density
87. `lrecon/op_inspect_adb_package.go` — inspect_adb_package: version and requested permissions of one package via dumpsys package
88. `lrecon/op_inspect_adb_window.go` — inspect_adb_window: current focus and focused app from dumpsys window on the attached device
89. `lrecon/op_inspect_address_context.go` — inspect_address_context: block, function, symbol and instruction at LRECON_AT (ghidra headless)
90. `lrecon/op_inspect_analysis_settings.go` — analysis settings op: deep, maxBytes, minString from `<state>`/config.json, source defaults when unset
91. `lrecon/op_inspect_analysis_view.go` — artifact view op: digest, json, symbols, skipped, notes or first 128 bytes as hex, 16 per row
92. `lrecon/op_inspect_android_class.go` — DEX class lookup: superclass, interfaces, source_file, access flags and field and method counts
93. `lrecon/op_inspect_android_method.go` — DEX method rows: walks one class_data_item ULEB chain for name, access flags and code_off
94. `lrecon/op_inspect_android_package.go` — APK/AAB package digest: package id, min and target sdk, permissions, capabilities and notes
95. `lrecon/op_inspect_apk_signature.go` — APK signing lineage: v1 PKCS#7 certs and v2/v3/v3.1 block IDs from the APK signing block
96. `lrecon/op_inspect_apktool_client.go` — apktool client: version, --help capabilities, JDK version from the release file and apktool.yml version
97. `lrecon/op_inspect_apple_ips.go` — .ips crash header: app_version, os_version, bug_type, timestamp, name and the body_parsed flag
98. `lrecon/op_inspect_artifact.go` — artifact digest in one read: kind, format, size, sha256, slices, toolchain, exports, hardening, notes
99. `lrecon/op_inspect_asset_catalog.go` — .car asset catalog: BOMStore block walk with block count and kinds, refusing CARV and non-catalogs
100. `lrecon/op_inspect_binary_layout.go` — section table for ELF, Mach-O and PE: name, address, file offset, size and exec flag, first fat slice
101. `lrecon/op_inspect_byte_entropy.go` — byte entropy: 4 KiB blocks with mean, min, max plus packed `>=7.5` and plain `<5` verdicts
102. `lrecon/op_inspect_dart_aot.go` — Dart AOT snapshot: magic, declared vs actual length, kind name, version hash and the JIT flag
103. `lrecon/op_inspect_desktop_application.go` — desktop app digest: electron version, asar files/main/product, unpacked native modules, IPC channels
104. `lrecon/op_inspect_devicetree.go` — flattened device tree walk: FDT version, node count, max depth, property count, model and compatible
105. `lrecon/op_inspect_electron_fuses.go` — Electron fuses: wire offset, version, count and per-fuse disabled/enabled/removed state from the sentinel
106. `lrecon/op_inspect_electron_page.go` — attached Electron tab: process.type probe, evaluate result and navigator.userAgent version extraction
107. `lrecon/op_inspect_elf_notes.go` — ELF note records from SHT_NOTE and PT_NOTE: owner, type, GNU build id hex, Go notes, printable payloads
108. `lrecon/op_inspect_erlang_beam.go` — BEAM IFF file: chunk id, size and offset table, Atom/AtU8 atom samples and CInf compiler version
109. `lrecon/op_inspect_evm_interface.go` — EVM interface: selectors from PUSH4 followed by EQ over raw or hex bytecode, refusing verified formats
110. `lrecon/op_inspect_firmware_regions.go` — firmware carve: container magic hits with offsets over the scan window, carrying firmware-ext skips
111. `lrecon/op_inspect_format_coverage.go` — format coverage: magic-switch kinds against the live readers, reporting supported_formats and reader_count
112. `lrecon/op_inspect_go_binary.go` — Go build info: toolchain, main module, deps, names and a build id marker scan of the first 64 KiB
113. `lrecon/op_inspect_gpu_code_objects.go` — NVIDIA fatbin: TLV ptx and cubin entries with payload size and offset, cubin arch mapped to sm_70..sm_90
114. `lrecon/op_inspect_il2cpp_metadata.go` — il2cpp global-metadata: version 16..31, string pool, TypeDef and MethodDef names with tokens, capped
115. `lrecon/op_inspect_jeb_client.go` — JEB client: class_def totals summed over classesN.dex with dex_files and the no-static-marker reason
116. `lrecon/op_inspect_kernel_module.go` — kernel module identity: Linux .modinfo key=value pairs or Mach-O __kmod_info name, version and id
117. `lrecon/op_inspect_keyed_archive.go` — NSKeyedArchiver bplist: $archiver, $top keys, $objects count and the $classname histogram
118. `lrecon/op_inspect_macho.go` — Mach-O digest: slices, minos, uuid, dylibs, rpaths, exports, symbols, hardening and the section table
119. `lrecon/op_inspect_managed_artifact.go` — .NET CLI metadata: runtime version, streams and BSJB row counts for TypeDef, Field, MethodDef, Assembly
120. `lrecon/op_inspect_managed_members.go` — .NET TypeDef rows with field and method ranges, method names and NestedClass-resolved enclosing types
121. `lrecon/op_inspect_managed_native_boundaries.go` — .NET P/Invoke boundaries: ImplMap and ModuleRef rows joining managed method to native entry and module
122. `lrecon/op_inspect_model_artifact.go` — model tensors: safetensors JSON header and GGUF tensor tables with dtype and shape or ggml type and offset
123. `lrecon/op_inspect_native_api.go` — native import table: format, import names and rows plus the truncated flag and an empty-table note
124. `lrecon/op_inspect_native_data_type.go` — Ghidra data type op: one named type from the analysis named by LRECON_NAME, route G
125. `lrecon/op_inspect_native_dispatch_metadata.go` — Ghidra dispatch metadata: ObjC and libdispatch bridge symbols with their call sites, route G
126. `lrecon/op_inspect_native_exports.go` — PE and ELF export count with symbol presence; a Mach-O target redirects to inspect_macho
127. `lrecon/op_inspect_native_instruction.go` — Ghidra instruction decode at LRECON_AT: length, p-code and flow, behind the Ghidra gate
128. `lrecon/op_inspect_native_load_image.go` — refusal stub: on-disk headers only, never a mapped DOS MZ/COM load image, stats path first
129. `lrecon/op_inspect_packet_capture.go` — pcap summary: format, packets, link type, time span, protocols, DNS names, SNI and URIs
130. `lrecon/op_inspect_packet_fields.go` — per-frame decode: netcDecode rows up to the frame cap with DNS, TLS and HTTP counts and a truncation note
131. `lrecon/op_inspect_pcap_capture.go` — thin alias registering the pcap summary run under the inspect_pcap_capture op name
132. `lrecon/op_inspect_pcap_client.go` — capture clients: HTTP UA/host and TLS SNI/ALPN/JA3 per client, family mapped from UA or JA3 md5
133. `lrecon/op_inspect_pe_certificates.go` — PE certificate table: WIN_CERTIFICATE entries, x509 fields, signer chain and image digest match verdict
134. `lrecon/op_inspect_pe_imports.go` — PE imports via debug/pe: DLL list and module and symbol rows, capped at 512 with total and shown
135. `lrecon/op_inspect_pe_load_config.go` — PE load config: GS cookie, SafeSEH and CFG tables, guard flag names, EH table and hotpatch fields
136. `lrecon/op_inspect_pe_resources.go` — .rsrc tree: type, name and language leaves with data RVA, file offset, size and codepage, cycle safe
137. `lrecon/op_inspect_plist.go` — plist keys from the Probe digest with bundle identity and version notes; non-plist targets skip
138. `lrecon/op_inspect_python_pyc.go` — CPython pyc: interpreter version from the magic, qualified names and capability notes
139. `lrecon/op_inspect_recorded_crash.go` — Apple .ips crash: exception type, signal and codes, loaded images and threads with triggered flag and frames
140. `lrecon/op_inspect_rust_binary.go` — Rust binary gate on the rustc toolchain prefix: crate list and rustsym: capability symbols
141. `lrecon/op_inspect_signal_decoders.go` — signal decoders: embedded decoders.json matched by name, modulation and symbol rate, query from LRECON_QUERY
142. `lrecon/op_inspect_signature.go` — Mach-O code signature: SuperBlob and CodeDirectory, cdhash, blob types and sealed page hash mismatches
143. `lrecon/op_inspect_sqlite_database.go` — SQLite database: page size, journal mode, table and virtual table list with CREATE statements
144. `lrecon/op_inspect_wasm_artifact.go` — WebAssembly module: section table with offsets and entry counts, import and export tables, LEB128 cursor
145. `lrecon/op_inspect_web_event_listeners.go` — attached tab listeners via CDP DOMDebugger: window and document rows with type, capture, passive, line
146. `lrecon/op_inspect_web_network_capture.go` — HAR 1.2 capture: entries with method, url, status, ms, bytes, mime type, totals and sorted hosts
147. `lrecon/op_inspect_web_page.go` — attached tab facts in one Runtime.evaluate: title, readyState, url, node count, html size, viewport
148. `lrecon/op_inspect_with_objdump.go` — objdump replacement: section and symbol tables of ELF, PE, Mach-O or an ar archive using debug/* only
149. `lrecon/op_install_adb_package.go` — APK install with adb install -r -t under a 5 min budget; the Success or Failure line decides, stderr quoted
150. `lrecon/op_instrument_with_frida.go` — refusal stub: live spawn, attach, inject and resume is not a static read, chain mapped to the driver
151. `lrecon/op_list_adb_devices.go` — adb devices -l table: serial, state, product, model and transport_id, answerable with no device attached
152. `lrecon/op_list_adb_directory.go` — device directory listing from adb shell ls -la: perm, links, owner, group, size, date, time, name
153. `lrecon/op_list_adb_features.go` — adb server host-features: comma-split feature list and count, distinct from the device pm feature list
154. `lrecon/op_list_adb_packages.go` — installed packages with APK paths from cmd package list packages -f, splitting at the last equals
155. `lrecon/op_list_adb_processes.go` — device process table from ps -A -o PID,USER,NAME,ARGS with layout inference and plain ps fallback
156. `lrecon/op_list_adb_services.go` — adb dumpsys -l: servicemanager service names the device is running, with a count
157. `lrecon/op_list_architectures.go` — Mach-O slice table: arch, cpu subtype, file offset, size and align for thin and fat images
158. `lrecon/op_list_bookmarks.go` — reads `<state>`/bookmarks.json and returns saved bookmarks, optionally filtered to one file
159. `lrecon/op_list_browser_targets.go` — CDP /json/list targets unfiltered with a type histogram, plus the browser websocket from /json/version
160. `lrecon/op_list_cutter_sessions.go` — running Cutter processes from the kernel table plus *.rzdb rizin projects in the standard dirs
161. `lrecon/op_list_documents.go` — session documents with per-path exists and size checks, flagging the currently selected one
162. `lrecon/op_list_electron_targets.go` — renderer execution contexts plus the isolated-world name to classify Electron, UA as weak signal
163. `lrecon/op_list_frida_devices.go` — host row plus adb devices -l: the frida device table read without frida (final.md y34)
164. `lrecon/op_list_frida_processes.go` — host kernel table or adb shell ps -A: the frida process table read without frida (y35)
165. `lrecon/op_list_javascript_runtime_targets.go` — Target.getTargets unfiltered as id, type, title, url, attached; lists without attaching
166. `lrecon/op_list_jeb_units.go` — class and method names from classes*.dex class_defs to type_ids to string_ids and class_data
167. `lrecon/op_list_names.go` — symbol count from Ghidra with a bounded address/name/type sample split into parsed, shown, truncated
168. `lrecon/op_list_procedures.go` — Ghidra headless function and external counts plus a bounded name/entry/size sample
169. `lrecon/op_list_segments.go` — Ghidra headless memory blocks with start, end, permissions and total bytes
170. `lrecon/op_list_strings.go` — printable ASCII and UTF-16LE strings in data sections with address, file offset and cut values
171. `lrecon/op_list_unknowns.go` — Ghidra pass over undefined ranges: start, end, length, total undefined bytes, capped at 100
172. `lrecon/op_load_frida_script.go` — refuses live Frida script load: lrecon reads static files and never injects an agent (y36)
173. `lrecon/op_match_native_functions.go` — Ghidra headless grouping of functions whose bodies are byte-identical; no FunctionID database
174. `lrecon/op_meta_util.go` — shared META state files, atomic writes, job JSON, Ghidra Meta.java runner, section lookup, CLI reader
175. `lrecon/op_metab_util.go` — DEX invoke-opcode walker for call edges plus PE image base and pointer width for P/Invoke
176. `lrecon/op_modes.go` — shared --compact, --count-only, --by/--top, --fields shapers and the coverage envelope on answers
177. `lrecon/op_native_cache.go` — Ghidra project cache keyed on binary bytes, engine version and script; flock, prune, stored answers
178. `lrecon/op_native_util.go` — Ghidra headless runner plus ELF/Mach-O/PE section, function, string, pattern and import readers
179. `lrecon/op_netc_util.go` — bounded pcap/pcapng reader, L2-L4 decoder, DNS/SNI/JA3/HTTP extractors and Mach-O dylib search order
180. `lrecon/op_next_address.go` — advances the session cursor to the next function start and saves the name to the session file
181. `lrecon/op_observe_javascript_runtime.go` — CDP Runtime/Debugger enable plus a 1s window: scriptParsed, console and exception rows (y71)
182. `lrecon/op_observe_native_calls.go` — refuses frida-trace runtime tracing; the static answer is Ghidra xrefs, call graph or pseudo-code (y37)
183. `lrecon/op_observe_native_ui.go` — adb uiautomator dump to a fresh /data/local/tmp path, cat, count nodes, then rm (final.md y38)
184. `lrecon/op_observe_web_execution.go` — CDP Runtime/Debugger/Log/Page enable before navigate, then console, log and error counts
185. `lrecon/op_observe_web_session.go` — CDP Target.setDiscoverTargets over 1.5s: created, changed and destroyed target ledger rows
186. `lrecon/op_open_binary.go` — binary digest identity from Probe: kind, format, size, sha256, gitoid; handle reported as none
187. `lrecon/op_open_bundle_resources.go` — BOMStore .car decode: RENDITIONS and FACETKEYS trees to asset, type, compression, offset, size rows
188. `lrecon/op_open_jeb_project.go` — apktool d into `<apk>`.jebproj via tmp dir plus rename, reused while the APK entry sha256 mark matches
189. `lrecon/op_prev_address.go` — moves the session cursor back to the previous function start and saves it to the session file
190. `lrecon/op_procedure_address.go` — Ghidra headless procedure_address: address of the function named by LRECON_NAME or LRECON_AT
191. `lrecon/op_procedure_assembly.go` — Ghidra headless procedure_assembly: instruction listing of the function named by LRECON_AT or NAME
192. `lrecon/op_procedure_callees.go` — Ghidra headless procedure_callees: the functions the named function calls
193. `lrecon/op_procedure_callers.go` — Ghidra headless procedure_callers: call sites that reach the named function
194. `lrecon/op_procedure_info.go` — Ghidra headless procedure_info: entry, size, signature and metadata for the named function
195. `lrecon/op_procedure_pseudo_code.go` — Ghidra headless procedure_pseudo_code: decompiler C for the function at LRECON_AT or LRECON_NAME
196. `lrecon/op_procedure_references.go` — Ghidra headless procedure_references: data and code xrefs inside the named function
197. `lrecon/op_project_android_application_graph.go` — APK graph: package, manifest components and permissions, dex classes with contains and extends edges
198. `lrecon/op_project_apple_application_graph.go` — macOS/iOS bundle graph: Info.plist keys, app.asar, asar.unpacked and libapp.so nodes with edges
199. `lrecon/op_project_harmony_application_graph.go` — HAP graph: module.json identity and abilities, .abc modules and libs/*.so with member sha256
200. `lrecon/op_project_managed_application_graph.go` — .NET assembly graph: module, assembly, refs, CLI types with contains, extends, references edges
201. `lrecon/op_pull_adb_file.go` — adb pull `<remote>`:`<local>` then a device stat -c %s size check plus the local sha256
202. `lrecon/op_pull_adb_package.go` — adb pm path `<pkg>` then one pull per split into -o DIR, with per-split sizes and a count
203. `lrecon/op_push_adb_file.go` — adb push `<local>`:`<remote>` then a device stat -c %s readback so a short write is reported
204. `lrecon/op_read_adb_logcat.go` — adb logcat -d -t 2000 parsed to threadtime rows: pid, tid, level, tag, msg and unparsed count
205. `lrecon/op_read_adb_setting.go` — adb shell settings get for one `<namespace>`:`<key>` in system, secure or global, unset when null
206. `lrecon/op_read_bytes.go` — hex and ASCII dump of LRECON_LEN bytes at LRECON_AT via section, segment or file offset
207. `lrecon/op_read_function_instructions.go` — Ghidra headless instruction list for the function named by LRECON_NAME or LRECON_AT
208. `lrecon/op_reconcile_javascript_runtime.go` — joins Debugger.scriptParsed URLs and exports keys with a local bundle's export table over CDP
209. `lrecon/op_record_unknown.go` — appends one address, its 16 bytes and a hypothesis to `<state>`/unknowns.json, refusing duplicates
210. `lrecon/op_recover_javascript_sources.go` — writes source map sourcesContent back to `<script>`.sources/, refusing names that escape the tree
211. `lrecon/op_refuse_util.go` — shared refusal text for the frida, rizin and cutter ops, each mapped to a static Ghidra op
212. `lrecon/op_resolve_adb_packages.go` — adb cmd package resolve-activity --components for `<action>`,`<uri>`: package and activity pairs
213. `lrecon/op_resolve_containing_procedure.go` — Ghidra headless function containing LRECON_AT, with the offset of that address into it
214. `lrecon/op_resolve_native_call_targets.go` — Ghidra headless call flows and references leaving the instruction at LRECON_AT
215. `lrecon/op_resume_frida_session.go` — refuses live Frida session resume: no spawn is held by lrecon, so nothing is left to resume (y45)
216. `lrecon/op_rizin_debug_command.go` — refuses live rizin debug commands; the batch lldb equivalents are gdb_console and gdb_session_status (y46)
217. `lrecon/op_rizin_debug_session_status.go` — refuses rizin debug session status: no live inferior, gdb_session_status is the batch answer (y47)
218. `lrecon/op_rt2_util.go` — one-shot adb, frida and gdb adapter: device gate, transfer and APK timeouts, stable failure text
219. `lrecon/op_rt_util.go` — external tool runner for the device ops: timeout, group kill, tail buffer, adb gate, PNG IHDR check
220. `lrecon/op_scrub_output.go` — scans a file or stdin for secret-shaped runs, reporting only offset, pattern id and length
221. `lrecon/op_search_android_classes.go` — DEX string_ids and type_ids class index matched against LRECON_QUERY, joined to class_defs
222. `lrecon/op_search_bytes.go` — search_bytes: matches a wildcard pattern like 48 8b ?? c3 and returns hit addresses plus scan caps
223. `lrecon/op_search_procedures.go` — search_procedures: case-insensitive function-name substring search through Ghidra headless
224. `lrecon/op_search_strings.go` — search_strings: case-insensitive LRECON_QUERY substring search over ASCII and UTF-16LE strings
225. `lrecon/op_set_address_name.go` — set_address_name: names the function at one address in a headless Ghidra project, reports stored name
226. `lrecon/op_set_addresses_names.go` — set_addresses_names: applies a list of address/name labels in one headless run and reports each
227. `lrecon/op_set_bookmark.go` — set_bookmark: writes {file,address,note,created} rows to bookmarks.json under one lock, keeps created
228. `lrecon/op_set_comment.go` — set_comment: stores a Ghidra pre-comment at one address and reports the value the project kept
229. `lrecon/op_set_inline_comment.go` — set_inline_comment: stores a Ghidra end-of-line comment for one address and reports it back
230. `lrecon/op_start_adb_activity.go` — start_adb_activity: adb am start -W -n pkg/activity, status line parsed to ok or timeout
231. `lrecon/op_start_adb_app.go` — start_adb_app: adb am start -W with MAIN/LAUNCHER intent for one package, reports its status
232. `lrecon/op_start_frida_session.go` — start_frida_session: refuses live attach/spawn as out of scope and points at the caller's driver
233. `lrecon/op_start_gdb_session.go` — start_gdb_session: refuses live gdb/lldb debugging, kind no_engine with the static alternatives
234. `lrecon/op_start_rizin_debug_session.go` — start_rizin_debug_session: refuses live rizin -d before any process starts, scope is static files
235. `lrecon/op_static_util.go` — shared STATIC helpers: capped whole-file reads, endian readers, CLR table view, DEX class and method walks
236. `lrecon/op_staticfmt_util.go` — shared PE header reader with data directories and section mapping for the cert, load-config and resource ops
237. `lrecon/op_stop_adb_app.go` — stop_adb_app: adb shell am force-stop on one package, reports stopped plus the shell output lines
238. `lrecon/op_trace_android_references.go` — trace_android_references: DEX class_data_item and invoke edges for a queried class or method, 200-edge cap
239. `lrecon/op_trace_application_feature.go` — trace_application_feature: Ghidra caller chain from one address to a depth given by job count, default 16
240. `lrecon/op_trace_call_path.go` — trace_call_path: bounded breadth-first Ghidra walk from LRECON_FROM to LRECON_TO, returns depth and path
241. `lrecon/op_trace_dylib_resolution.go` — trace_dylib_resolution: Mach-O load dylib commands resolved via @loader_path, @executable_path and rpath
242. `lrecon/op_trace_feature.go` — trace_feature: maps one address to offset/section/symbol/bytes or finds literal string hits and addresses
243. `lrecon/op_trace_javascript_semantics.go` — trace_javascript_semantics: CDP breakpoint at URL:line on the attached page, pause locations, then resume
244. `lrecon/op_trace_native_ui_action.go` — trace_native_ui_action: adb getevent -lt evdev lines decoded to device, type, code and value per event
245. `lrecon/op_trace_native_values.go` — trace_native_values: refuses live Frida onEnter/onLeave value reads, names Ghidra xrefs and pseudocode
246. `lrecon/op_trace_web_module_imports.go` — trace_web_module_imports: DFS over import/require edges from one entry script into resolved, missing, external rows
247. `lrecon/op_trace_web_source_location.go` — trace_web_source_location: decodes source map v3 VLQ mappings into generated to original file/line/column rows
248. `lrecon/op_uninstall_adb_package.go` — uninstall_adb_package: pm uninstall --user 0, decides on the status line and labels the scope as user 0
249. `lrecon/op_unload_frida_script.go` — unload_frida_script: refuses live script unload, lrecon never injects or keeps a session
250. `lrecon/op_unset_bookmark.go` — unset_bookmark: removes the bookmark row for an address from bookmarks.json, absence is an error
251. `lrecon/op_update_analysis_settings.go` — update_analysis_settings: writes deep, maxBytes and minString into config.json, unset fields keep values
252. `lrecon/op_update_unknown.go` — update_unknown: rewrites the hypothesis or resolution of an unknown keyed by address in unknowns.json
253. `lrecon/op_verify_adversarial.go` — verify_target_immutability and verify_output_equivalence: re-hash target or reconstruction to prove bytes
254. `lrecon/op_verify_managed_native_boundaries.go` — verify_managed_native_boundaries: per ImplMap, decodes the jmp [IAT] thunk and matches the named PE import
255. `lrecon/op_verify_reconstruction.go` — verify_reconstruction: re-reads every {offset,length,expect} claim from the artifact and compares bytes
256. `lrecon/op_verify_unknown_resolution.go` — verify_unknown_resolution: re-reads an unknown's bytes and resolution, writes state only when both agree
257. `lrecon/op_web_util.go` — WEB plumbing: bounded text reads, JS lexer and import edges, one exec'd CDP driver, source-map VLQ decode
258. `lrecon/op_xrefs.go` — xrefs: Ghidra references to and from LRECON_AT or the symbol named by LRECON_NAME

### Core — 72 files

259. `lrecon/asar.go` — asar header tree walk: member counts, native/wasm/sqlite caps, preload bridges, IPC channels, source maps
260. `lrecon/beam.go` — BEAM reader: FOR1/BEAM IFF walk taking module name and imports from AtU8 atoms, version from CInf
261. `lrecon/beamdbgi.go` — BEAM debug-info post pass: unzips Dbgi/Abst, decodes ETF, lists each function/arity with source line
262. `lrecon/bound.go` — allocCeil: the one gate turning a declared digest length into an allocation, refusing fields with no spec max
263. `lrecon/bundle.go` — macOS .app inspector: opens Resources/app.asar or the CFBundleExecutable binary the wrapper points at
264. `lrecon/cdp.go` — DevTools transport in Go: /json/list and /json/version GETs, RFC 6455 client, JSON-RPC steps, event collect
265. `lrecon/claims.go` — two-witness settlement: emit() turns language/producer proposals into Claims, Unknown or Conflicts
266. `lrecon/compress.go` — single-stream wrapper headers (gzip, bzip2, xz, lzma, lz4, zstd) plus one-level gzip and bzip2 decode
267. `lrecon/constants.go` — crypto table search (AES sbox, SHA-256 K/IV, ChaCha sigma, MD5, curve25519) plus JIT import tokens
268. `lrecon/cxxvtable.go` — Itanium C++ vtables on x86-64 ELF: _ZTV slots via RELA, RTTI base edges and slot function names
269. `lrecon/dart.go` — Dart snapshot reader: magic, length and kind (full/jit/aot/module) plus the version hash it declines to map
270. `lrecon/detect.go` — Probe entry: magic-first kind routing to the readers, sha256 and git blob OID identity, reason gate
271. `lrecon/dex.go` — dex evidence: map_list cross-check and string or archive markers naming Jiagu, Bangcle, Baidu, Mobisec packers
272. `lrecon/digest_contract.go` — digest field contract: documents "" vs null vs [] meaning for absent, unmeasured and measured-none values
273. `lrecon/dispatch.go` — reader registry: register() contract checks plus the magic-reader pass and post-reader second pass
274. `lrecon/dotnetsf.go` — .NET single-file bundle: 32-byte marker, header table entries with kind and sidecar runtime version
275. `lrecon/errors.go` — refusal envelope and classify(): one JSON object on stdout with an error kind, exit status 2
276. `lrecon/evidence.go` — canonical digest JSON sha256 evidence line and ExplainField attribution of a field to claim, offset, rule
277. `lrecon/evm.go` — EVM post reader: Solidity CBOR metadata trailer, solc version and ipfs/bzzr0/bzzr1 keys, no opcodes
278. `lrecon/extops.go` — external-tool op table: registerExtOp/runExtOp plus sorted names behind --ext-op and --list-ext-ops listings
279. `lrecon/extract.go` — extract and extract-all payload writers for zip/apk/ipa and asar with per-member and tree byte caps
280. `lrecon/exttool.go` — external-tool plumbing: per-item deadlines, typed refusals, adb/lldb/jadx/apktool/analyzeHeadless runners
281. `lrecon/firmware.go` — firmware reader: container magic at offset 0 plus carved squashfs/ubi/cramfs/trx/uimage/dtb hits with offsets
282. `lrecon/firmware_ext.go` — firmware header verification: UBI, UBIFS, JFFS2, TRX, uImage, SEAMA, SHRS, sparse, bootimg CRC and length checks
283. `lrecon/formats.go` — SQLite, plist and code-signature readers: page size, WAL flag, writer version, bplist or XML key lists
284. `lrecon/java.go` — Java class reader: CAFEBABE, class version and constant pool naming this_class, refusing module-info
285. `lrecon/klib.go` — Kotlin .klib reader: manifest abi and metadata versions plus class and package names from .knm linkdata
286. `lrecon/lsda.go` — Itanium C++ exception tables: .eh_frame FDE to LSDA call sites, action chains and _ZTI catch types
287. `lrecon/lsdamacho.go` — Mach-O C++ LSDA post pass: LSDA addresses from __unwind_info or GCC_except_table, reusing parseLSDA
288. `lrecon/lua.go` — Lua reader: luac 5.1-5.4 header checks with LUAC_INT/NUM sentinels, LuaJIT dump version and flags
289. `lrecon/luaproto.go` — Lua 5.3/5.4 prototype tree: source name, line range, params, local and upvalue names per function
290. `lrecon/main.go` — CLI entry: flag set for --op, --list-ops, --plan, --next, --diff, --extract, --json and the run dispatch
291. `lrecon/managed.go` — managed depth: .NET CLI metadata streams and pinvoke modules for PE, Unity IL2CPP markers for natives
292. `lrecon/managed_cil.go` — ECMA-335 CIL disassembly for decompile_all: MethodDef RVAs decoded into per-method IL opcode listings
293. `lrecon/mangling.go` — mangling family classifier: counts Itanium, MSVC, Rust v0/legacy, Swift, ObjC, Go symbol names
294. `lrecon/mobile.go` — mobile archives: DEX header and string-pool class names, binary AndroidManifest XML, apk/aab/ipa entry tables
295. `lrecon/move.go` — Move bytecode reader: magic, version 5-6, table directory and the module-handle name from identifiers
296. `lrecon/msvcrti.go` — MSVC C++ RTTI: CompleteObjectLocator, hierarchy and base descriptors resolved to class names in PE and COFF
297. `lrecon/native.go` — native digest: Mach-O/ELF/PE load commands, dylibs, exports, hardening, Go buildinfo and Rust markers
298. `lrecon/notes.go` — deepNote helper: prefixes tool-agnostic next-step strings with "deep: " before appending to Digest notes
299. `lrecon/objc.go` — Objective-C post reader: __objc_classname/methname/methtype name blocks plus classlist pointer count
300. `lrecon/objectsyms.go` — nm-free symbol table: ELF, Mach-O and PE symbols as value, nm kind letter and name, sorted by address
301. `lrecon/ocaml.go` — OCaml container reader: Caml1999 magic at offset 0 or EOF-12, section count and TOC names for cmo/cma/cmxs
302. `lrecon/ops.go` — op registry: name, route L/G/Y, description and run func per inventory item, dispatch and needs rules
303. `lrecon/pblite.go` — protobuf-lite wire walker: tag plus wire 0/1/2/5 payloads, nested messages and varint int32 slices, no schema
304. `lrecon/pcap.go` — pcap and pcapng reader: packet count, link type, time span, protocols, DNS, SNI and HTTP URIs from frames
305. `lrecon/php.go` — PHP artifacts: OPCACHE file-cache headers and phar stub plus manifest with entries, compression and signature
306. `lrecon/pkgjs.go` — packaged JS runtimes: pkg, Bun trailer, deno compile and Node SEA payloads located in Mach-O, ELF or PE hosts
307. `lrecon/plan.go` — planFor: kind to first op and next ops map, builds the paste-ready command and promises its result keys
308. `lrecon/proc_unix.go` — POSIX process helpers: new group per child, group kill and liveness probes, flock advisory locks
309. `lrecon/proc_windows.go` — Windows process helpers: taskkill /T tree kill, liveness probe and LockFileEx exclusive lock
310. `lrecon/proctable.go` — procRow type shared by the in-process process table readers: pid plus kernel command name
311. `lrecon/proctable_darwin.go` — darwin process table via sysctl kern.proc.all: pid and p_comm rows at fixed kinfo_proc offsets
312. `lrecon/proctable_linux.go` — linux process table from /proc/`<pid>`/comm, numeric entries only, vanished pids skipped
313. `lrecon/proctable_other.go` — process table stubs for platforms other than darwin and linux: both lookups return a named gap
314. `lrecon/producer.go` — producer reader: compiler and version from .comment, DW_AT_producer, build version and CodeView strings
315. `lrecon/pyc.go` — CPython .pyc: magic-to-version table, header layout per release and one marshalled code object decoded
316. `lrecon/readcap.go` — readCapped: reads a file only up to limit and errors when it is over, never a silent prefix
317. `lrecon/reasons.go` — reason registry: one closed skip vocabulary per reader field, with lookups and digest validation
318. `lrecon/rlib.go` — Rust .rlib ar archive: lib.rmeta metadata version string and codegen-unit crate names, post reader only
319. `lrecon/roles.go` — dep and dylib role labels, updater framework caps and the --diff line renderer for two digests
320. `lrecon/rustsym.go` — Rust symbol demangler: legacy _ZN and v0 _R paths, drop glue and panic glue classified, unverified refused
321. `lrecon/signals.go` — temp tree sweeping with pid ownership, signal reaper for tracked child process groups
322. `lrecon/sigpack.go` — embedded sigpack.json markers matched in one pass; a hit is one witness, never a language claim alone
323. `lrecon/skeleton.go` — linker skeleton: which code intervals pclntab, function starts or FDE tables claim, with coverage ratio
324. `lrecon/skipped.go` — Skip, Coverage and Claim types plus the digest skip, parsed, scanned and witness-aware completeness rules
325. `lrecon/swift.go` — Swift metadata sections: type, protocol, fieldmd and typeref counts per Mach-O slice or ELF image
326. `lrecon/swiftfield.go` — Swift field metadata: field names from fieldmd and reflstr paired with type metadata for proven layout
327. `lrecon/types.go` — digest contract types: Target, Dep, Digest and the fixed-budget Text rendering an agent reads
328. `lrecon/v8cache.go` — V8 code cache: serialized-data header generation from magic, version and source hashes, payload length checked
329. `lrecon/wasm.go` — WebAssembly: LEB128 section walk for imports, exports, limits and the producers and name custom sections
330. `lrecon/witness.go` — Witness type and disjoint-range algebra: two classes on separate byte ranges before a claim stands
