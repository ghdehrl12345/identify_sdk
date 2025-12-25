# identify-sdk

Zero-knowledge proof security toolkit for passwordless authentication and privacy-preserving verification.

## Installation

```bash
npm install identify-sdk
```

## Quick Start

```javascript
const { init } = require('identify-sdk');

async function main() {
  // Initialize the SDK
  const client = await init();

  // Generate authentication proof
  const result = client.generateProof(
    "user_password",      // secret
    2000,                 // birth year
    { targetYear: 2025, limitAge: 20 },
    serverChallenge,      // from server
    saltHex               // from server
  );

  // Send result.proof and result.hash to server for verification
  console.log(result.proof, result.hash);
}

main();
```

## API

### `init(options?): Promise<IdentifyClient>`

Initialize the SDK and return a client.

**Options:**
- `wasmPath` - Custom path to identify.wasm
- `provingKeyPath` - Custom path to user.pk
- `config` - Default configuration

### `client.generateProof(secret, birthYear, config, challenge, saltHex)`

Generate a ZKP authentication proof.

**Parameters:**
- `secret` - User's password/secret
- `birthYear` - User's birth year
- `config` - `{ targetYear, limitAge }`
- `challenge` - Server-issued challenge (number)
- `saltHex` - Salt in hex format

**Returns:**
```javascript
{
  proof: "hex string",
  hash: "commitment string",
  binding: "binding string",
  salt: "salt hex"
}
```

### `client.generateAgeProof(birthYear, config)`

Generate an age-only verification proof.

## TypeScript

TypeScript types are included:

```typescript
import { init, Config, ProofResult } from 'identify-sdk';
```

## Server-Side Verification

Use the Go SDK for server-side verification:

```bash
go get github.com/ghdehrl12345/identify_sdk/v2@latest
```

```go
import "github.com/ghdehrl12345/identify_sdk/v2/auth"

verifier, _ := auth.NewVerifier()
ok, _ := verifier.VerifyLogin(proofBytes, commitment, salt, challenge)
```

## License

MIT
