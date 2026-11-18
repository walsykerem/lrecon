# lrecon

Bytes-only reverse engineering in one binary. Points at a file, returns a verdict.

```sh
npx lrecon target.apk
npx lrecon --json target.ipa
npx lrecon --op inspect_go_binary target.bin
npx lrecon --list-ops --json
```

235 inventory ops and 80 runtime ops over Mach-O, ELF, PE, APK/IPA, Java, .NET, Dart, wasm, Electron/asar, firmware images and more. It reads the bytes and never executes the artifact.

Bundled binaries: `darwin-arm64`, `darwin-x64`, `linux-x64`, `linux-arm64`, `win32-x64`. Anything else, build from source with `go build ./lrecon`.

Docs, output contract, exit codes: https://github.com/walsykerem/lrecon

MIT © 2026 Kerem Urhan
