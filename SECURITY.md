# Security policy

## Reporting a vulnerability

If you discover a security issue in `@bedrockgovernance/notary` — a
canonicalisation bug, a false-positive verifier, or any side
effect beyond reading the input — please report it privately to
`security@bedrockgovernance.com`. Do not open a public issue.

We will acknowledge receipt within two business days and provide a
target fix date within five.

## Threat model

`@bedrockgovernance/notary` is a deterministic, read-only verifier. It
holds no secrets and makes no network calls. A `valid: true` result
must imply the underlying signing key actually signed the record
and the record was not modified after signing.

## Out of scope

- Bugs in the wider Bedrock platform.
- Issues in third-party signers built against the `Signer` interface.
