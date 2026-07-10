# Changelog

All notable changes to `@bedrockgovernance/notary` will be documented in
this file. The format is based on [Keep a Changelog][keep] and the
package adheres to [Semantic Versioning][semver].

[keep]: https://keepachangelog.com/en/1.1.0/
[semver]: https://semver.org/spec/v2.0.0.html

## [Unreleased]

## [0.2.0] — 2026-07-10

### Changed

- **Renamed the package** from `@bedrockcompliance/notary` to
  `@bedrockgovernance/notary`. Update your dependency and imports; the
  API is otherwise unchanged. The old package name is no longer
  published.

### Added

- `verifyChain` accepts an optional `trustedPublicKeys` set
  (`VerifyChainOptions`). When provided, each record's ECDSA signature
  is verified and pinned to the trusted set once its structural checks
  pass — a record forged with its own key is rejected as
  `SIGNATURE_INVALID` even though its hash chain is self-consistent.
  Omitting the option preserves the previous structure-only behaviour.

## [0.1.1] — 2026-04-10

### Added

- Optional `payload` field on `LedgerRecordProjection` for full record
  hash verification. When present, `verifyChain` recomputes `recordHash`
  from the canonical payload and flags `HASH_MISMATCH` if it differs.
- Malformed payloads produce `HASH_MISMATCH` instead of throwing.

### Changed

- Publish workflow switched to OIDC trusted publishing (no token).
- Updated README and package description to cover both compute and verify.

## [0.1.0] — 2026-04-09

### Added

- Initial release.
- `canonicalise(value)` — Bedrock canonical JSON serialiser.
- `sha256(string)` and `sha256Buffer(buffer)` — SHA-256 helpers.
- `computeRecordHash(payload)` — record-hash primitive.
- `computeChainHash(recordHash, previousHash)` — chain-hash primitive.
- `verifyChain(records, firmId)` — full chain integrity verifier.
- `verifySignature(record, options?)` — ECDSA P-256 signature verifier
  with optional trusted-key pinning and curve enforcement.
- `verifyCertificate(input, options?)` — end-to-end certificate verifier.
- `Signer` interface for third-party signing implementations.
- `ChainInvalidReason`, `GENESIS_HASH`, `SIGNING_ALGORITHM` constants.
