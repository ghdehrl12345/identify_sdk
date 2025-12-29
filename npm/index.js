const fs = require("fs");
const path = require("path");

// Load Go's wasm JS runtime
require("./dist/wasm_exec.js");

/**
 * Check if running in production mode.
 * @returns {boolean}
 */
function isProduction() {
  return process.env.NODE_ENV === "production";
}

/**
 * Sanitize error message for production.
 * In production, hides internal details and returns generic message.
 * @param {string} message - Original error message
 * @param {string} genericMessage - Generic message for production
 * @returns {string}
 */
function sanitizeError(message, genericMessage = "An error occurred") {
  if (isProduction()) {
    // Extract error code if present (e.g., "E1001: ...")
    const codeMatch = message.match(/^(E\d{4}):/);
    if (codeMatch) {
      return `${codeMatch[1]}: ${genericMessage}`;
    }
    return genericMessage;
  }
  return message;
}

/**
 * Initialize the WASM prover runtime.
 * @param {Object} opts - Options
 * @param {string} [opts.wasmPath] - Path to identify.wasm
 * @param {Uint8Array|Buffer} [opts.wasmBytes] - In-memory wasm bytes
 * @param {string} [opts.provingKeyPath] - Path to user.pk
 * @param {Uint8Array|Buffer} [opts.provingKeyBytes] - In-memory proving key
 * @param {Object} [opts.config] - Configuration { targetYear, limitAge, argonMemory, argonIterations }
 * @returns {Promise<IdentifyClient>}
 */
async function init(opts = {}) {
  const distDir = path.join(__dirname, "dist");
  const wasmFile = opts.wasmPath || path.join(distDir, "identify.wasm");
  const pkFile = opts.provingKeyPath || path.join(distDir, "user.pk");

  const wasmBinary = opts.wasmBytes || (await fs.promises.readFile(wasmFile));
  const pkBytes = opts.provingKeyBytes || (await fs.promises.readFile(pkFile));

  if (typeof Go !== "function") {
    throw new Error(sanitizeError("E4001: Go runtime (wasm_exec.js) not loaded", "Runtime initialization failed"));
  }

  const go = new Go();
  const { instance } = await WebAssembly.instantiate(wasmBinary, go.importObject);

  // Start Go runtime
  go.run(instance);
  await new Promise((resolve) => setTimeout(resolve, 0));

  if (typeof global.InitIdentify !== "function") {
    throw new Error(sanitizeError("E4002: InitIdentify function not found", "Initialization failed"));
  }

  const ok = global.InitIdentify(new Uint8Array(pkBytes), opts.config || {});
  if (ok !== true) {
    throw new Error(sanitizeError("E4003: InitIdentify failed", "Initialization failed"));
  }

  if (typeof global.GenerateIdentifyProof !== "function") {
    throw new Error(sanitizeError("E4004: GenerateIdentifyProof function not found", "Initialization failed"));
  }

  return new IdentifyClient();
}

/**
 * IdentifyClient provides ZKP proof generation methods.
 */
class IdentifyClient {
  /**
   * Generate a ZKP authentication proof.
   * @param {string} secret - User's secret (password)
   * @param {number} birthYear - User's birth year
   * @param {Object} config - { targetYear, limitAge }
   * @param {number} challenge - Server-issued challenge
   * @param {string} saltHex - Salt in hex format
   * @returns {{ proof: string, hash: string, binding: string, salt: string }}
   */
  generateProof(secret, birthYear, config, challenge, saltHex) {
    const cfg = config || {};
    const res = global.GenerateIdentifyProof(
      secret,
      birthYear,
      cfg,
      challenge || 0,
      saltHex || ""
    );
    if (typeof res === "string" && res.startsWith("Error")) {
      throw new Error(sanitizeError(res, "Proof generation failed"));
    }
    return {
      proof: res.proof,
      hash: res.hash,
      binding: res.binding,
      salt: res.salt,
      pkId: res.pkId,
      policyYear: res.policyYear || cfg.targetYear,
      limitAge: res.limitAge || cfg.limitAge,
    };
  }

  /**
   * Generate an age-only proof.
   * @param {number} birthYear - User's birth year
   * @param {Object} config - { targetYear, limitAge }
   * @returns {{ proof: string }}
   */
  generateAgeProof(birthYear, config) {
    const cfg = config || {};
    const res = global.GenerateAgeProof(birthYear, cfg);
    if (typeof res === "string" && res.startsWith("Error")) {
      throw new Error(sanitizeError(res, "Age proof generation failed"));
    }
    return {
      proof: res.proof,
      pkId: res.pkId,
      policyYear: res.policyYear,
      limitAge: res.limitAge,
    };
  }
}

module.exports = { init, IdentifyClient, isProduction, sanitizeError };

