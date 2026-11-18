#!/usr/bin/env node
"use strict";

const { spawn } = require("node:child_process");
const path = require("node:path");

const key = `${process.platform}-${process.arch}`;
const file = path.join(
  __dirname,
  "bin",
  `lrecon-${key}${process.platform === "win32" ? ".exe" : ""}`,
);

const child = spawn(file, process.argv.slice(2), { stdio: "inherit" });

child.on("error", () => {
  console.error(
    `lrecon: no bundled binary for ${key}. Build from source: go build ./lrecon`,
  );
  process.exit(1);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => child.kill(signal));
}

child.on("exit", (code, signal) => process.exit(signal ? 1 : code));
