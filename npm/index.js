const fs = require("fs");
const path = require("path");

// Load Go's wasm JS runtime (sets global.Go)
require("./dist/wasm_exec.js");

/**
 * Initialize the WASM prover runtime and load the proving key.
 * @param {Object} opts
 * @param {string} [opts.wasmPath] - Path to identify.wasm. Defaults to bundled dist/identify.wasm.
 * @param {Uint8Array|Buffer} [opts.wasmBytes] - Optional in-memory wasm bytes.
 * @param {string} [opts.provingKeyPath] - Path to user.pk. Defaults to bundled dist/user.pk.
 * @param {Uint8Array|Buffer} [opts.provingKeyBytes] - Optional in-memory proving key.
 * @returns {Promise<IdentifyClient>}
 */
async function init(opts = {}) {
  const distDir = path.join(__dirname, "dist");
  const wasmFile = opts.wasmPath || path.join(distDir, "identify.wasm");
  const pkFile = opts.provingKeyPath || path.join(distDir, "user.pk");

  const wasmBinary =
    opts.wasmBytes || (await fs.promises.readFile(wasmFile));
  const pkBytes =
    opts.provingKeyBytes || (await fs.promises.readFile(pkFile));

  if (typeof Go !== "function") {
    throw new Error("Go runtime (wasm_exec.js) not loaded");
  }

  const go = new Go();
  const { instance } = await WebAssembly.instantiate(wasmBinary, go.importObject);

  // Start Go runtime (non-blocking; returns a promise that resolves on exit)
  go.run(instance);
  await new Promise((resolve) => setTimeout(resolve, 0));

  if (typeof global.InitIdentify !== "function") {
    throw new Error("InitIdentify function not found on global");
  }
  const ok = global.InitIdentify(new Uint8Array(pkBytes), opts.config || {});
  if (ok !== true) {
    throw new Error("InitIdentify failed");
  }
  if (typeof global.GenerateIdentifyProof !== "function") {
    throw new Error("GenerateIdentifyProof function not found on global");
  }

  return new IdentifyClient();
}

class IdentifyClient {
  generateProof(secret, birthYear, config, challenge, saltHex) {
    const cfg = config || {};
    const res = global.GenerateIdentifyProof(secret, birthYear, cfg, challenge || 0, saltHex || "");
    if (typeof res === "string" && res.startsWith("Error")) {
      throw new Error(res);
    }
    res.pkId = res.pkId || undefined;
    res.policyYear = res.policyYear || cfg.targetYear || cfg.currentYear;
    res.limitAge = res.limitAge || cfg.limitAge;
    return res;
  }

  generateAgeProof(birthYear, config) {
    const cfg = config || {};
    const res = global.GenerateAgeProof(birthYear, cfg);
    if (typeof res === "string" && res.startsWith("Error")) {
      throw new Error(res);
    }
    return res;
  }
}

module.exports = { init, IdentifyClient };
