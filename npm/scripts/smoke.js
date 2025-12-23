#!/usr/bin/env node
const crypto = require("crypto");
const path = require("path");
const { execSync } = require("child_process");

console.log(">> Building dist artifacts");
execSync("npm run build --silent", { cwd: path.join(__dirname, ".."), stdio: "inherit" });

const { init } = require("../index");

async function main() {
  const { generateProof } = await init();
  const secret = "password123";
  const birthYear = 2000;
  const currentYear = 2025;
  const limitAge = 20;
  const challenge = 4242;
  const saltHex = crypto.randomBytes(16).toString("hex");

  const result = generateProof(secret, birthYear, currentYear, limitAge, challenge, saltHex);
  if (!result || !result.proof || !result.hash || !result.binding) {
    throw new Error("Invalid proof result");
  }
  console.log("✅ WASM smoke test passed");
}

main().catch((err) => {
  console.error("❌ WASM smoke test failed:", err);
  process.exit(1);
});
