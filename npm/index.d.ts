/**
 * Configuration options for the SDK.
 */
export interface Config {
    targetYear?: number;
    limitAge?: number;
    argonMemory?: number;
    argonIterations?: number;
}

/**
 * Initialization options.
 */
export interface InitOptions {
    wasmPath?: string;
    wasmBytes?: Uint8Array | Buffer;
    provingKeyPath?: string;
    provingKeyBytes?: Uint8Array | Buffer;
    config?: Config;
}

/**
 * Result of proof generation.
 */
export interface ProofResult {
    proof: string;
    hash: string;
    binding: string;
    salt: string;
    pkId?: string;
    policyYear?: number;
    limitAge?: number;
}

/**
 * Result of age proof generation.
 */
export interface AgeProofResult {
    proof: string;
    pkId?: string;
    policyYear?: number;
    limitAge?: number;
}

/**
 * Client for generating ZKP proofs.
 */
export declare class IdentifyClient {
    /**
     * Generate a ZKP authentication proof.
     * @param secret - User's secret (password)
     * @param birthYear - User's birth year
     * @param config - Configuration { targetYear, limitAge }
     * @param challenge - Server-issued challenge
     * @param saltHex - Salt in hex format
     */
    generateProof(
        secret: string,
        birthYear: number,
        config: Config,
        challenge: number,
        saltHex: string
    ): ProofResult;

    /**
     * Generate an age-only proof.
     * @param birthYear - User's birth year
     * @param config - Configuration { targetYear, limitAge }
     */
    generateAgeProof(birthYear: number, config: Config): AgeProofResult;
}

/**
 * Initialize the SDK and return a client.
 * @param opts - Initialization options
 */
export declare function init(opts?: InitOptions): Promise<IdentifyClient>;
