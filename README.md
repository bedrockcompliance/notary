# @bedrockgovernance/notary

> The hash and signature engine behind the
> [Bedrock](https://bedrockgovernance.com) immutable advice ledger.

`@bedrockgovernance/notary` contains the canonical JSON serialiser, the
record and chain hash functions, and the ECDSA P-256 signature
verifier that underpin the Bedrock ledger. The Bedrock platform
imports it on both the **write path** (computing hashes when records
are created) and the **verify path** (checking signatures when
certificates are verified), so there is no internal copy of the
algorithm — anyone running this package is running the same code
that runs in production.

No signing implementations, no private keys, no networking.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Install

```sh
npm install @bedrockgovernance/notary
```

## Quickstart

### Compute a record hash (same function the Bedrock writer uses)

```ts
import { computeRecordHash, computeChainHash, GENESIS_HASH } from '@bedrockgovernance/notary';

const recordHash = computeRecordHash(payload);
const chainHash = computeChainHash(recordHash, previousHash ?? GENESIS_HASH);
```

### Verify a certificate

```ts
import { verifyCertificate } from '@bedrockgovernance/notary';

const response = await fetch(
  `https://api.bedrockgovernance.com/v1/verify/${certificateId}`,
);
const { certificate, record } = await response.json();

const result = verifyCertificate({ certificate, record });
if (!result.valid) {
  throw new Error(`Certificate invalid: ${result.reason}`);
}
```

### Verify a chain

```ts
import { verifyChain } from '@bedrockgovernance/notary';

const result = verifyChain(records, firmId);
```

## API

**Compute:**
- `canonicalise(value)` — Bedrock's canonical JSON serialiser.
- `sha256(string)` / `sha256Buffer(buffer)` — SHA-256 helpers.
- `computeRecordHash(payload)` — `sha256(canonicalise(payload))`.
- `computeChainHash(recordHash, previousHash)` — chain binding.

**Verify:**
- `verifyChain(records, firmId)` — full chain integrity check.
- `verifySignature(record, options?)` — ECDSA P-256 verification
  with optional `trustedPublicKey` pinning.
- `verifyCertificate(input, options?)` — end-to-end certificate check.

**Constants:**
- `GENESIS_HASH`, `SIGNING_ALGORITHM`, `ChainInvalidReason`, `Signer`.

## License

[Apache 2.0](./LICENSE). See [`SECURITY.md`](./SECURITY.md) for
vulnerability reporting.
