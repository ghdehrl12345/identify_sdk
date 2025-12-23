#!/usr/bin/env node
const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const repoRoot = path.resolve(root, "..");
const distDir = path.join(root, "dist");

fs.mkdirSync(distDir, { recursive: true });

console.log(">> Building WASM (GOOS=js GOARCH=wasm)");
execSync(
  "GOOS=js GOARCH=wasm go build -o dist/identify.wasm github.com/ghdehrl12345/identify_sdk/client/wasm",
  {
    cwd: root,
    stdio: "inherit",
    env: {
      ...process.env,
      GOCACHE: path.join(repoRoot, ".gocache"),
    },
  }
);

console.log(">> Copying wasm_exec.js");
fs.copyFileSync(
  path.join(repoRoot, "html", "wasm_exec.js"),
  path.join(distDir, "wasm_exec.js")
);

console.log(">> Copying proving key");
fs.copyFileSync(
  path.join(repoRoot, "client", "user.pk"),
  path.join(distDir, "user.pk")
);

console.log("Done. Files ready in npm/dist/");
