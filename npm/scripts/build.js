const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const distDir = path.join(__dirname, "..", "dist");
const rootDir = path.join(__dirname, "..", "..");

console.log("🔨 Building identify-sdk npm package...\n");

// Ensure dist directory exists
if (!fs.existsSync(distDir)) {
    fs.mkdirSync(distDir, { recursive: true });
}

// Build WASM
console.log(">> Building WASM...");
try {
    execSync("GOOS=js GOARCH=wasm go build -o npm/dist/identify.wasm ./wasm", {
        cwd: rootDir,
        stdio: "inherit",
    });
} catch (err) {
    console.error("❌ WASM build failed");
    process.exit(1);
}

// Copy wasm_exec.js
console.log(">> Copying wasm_exec.js...");
const goRoot = execSync("go env GOROOT", { encoding: "utf-8" }).trim();
const wasmExecSrc = path.join(goRoot, "lib", "wasm", "wasm_exec.js");
const wasmExecDst = path.join(distDir, "wasm_exec.js");
fs.copyFileSync(wasmExecSrc, wasmExecDst);

// Copy proving key
console.log(">> Copying proving key...");
const pkSrc = path.join(rootDir, "auth", "user.pk");
const pkDst = path.join(distDir, "user.pk");
if (fs.existsSync(pkSrc)) {
    fs.copyFileSync(pkSrc, pkDst);
} else {
    console.warn("⚠️  user.pk not found, skipping...");
}

// Copy age proving key
const agePkSrc = path.join(rootDir, "age", "age.pk");
const agePkDst = path.join(distDir, "age.pk");
if (fs.existsSync(agePkSrc)) {
    fs.copyFileSync(agePkSrc, agePkDst);
} else {
    console.warn("⚠️  age.pk not found, skipping...");
}

console.log("\n✅ Build complete!");
console.log("   dist/identify.wasm");
console.log("   dist/wasm_exec.js");
console.log("   dist/user.pk");
console.log("   dist/age.pk");
