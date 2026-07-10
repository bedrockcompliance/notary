/**
 * ECDSA P-256 signature verification.
 *
 * @packageDocumentation
 */

import { createPublicKey, verify, type KeyObject } from 'node:crypto';

import { computeChainHash } from './hash';
import {
  ChainInvalidReason,
  type LedgerRecordProjection,
  type SignatureVerificationResult,
} from './types';

/**
 * Optional behaviour switches for {@link verifySignature}.
 */
export interface VerifySignatureOptions {
  /**
   * Base64-encoded SPKI DER public key the caller trusts. When
   * supplied, the verifier asserts the key embedded on the record
   * matches this trusted key byte-for-byte before checking the
   * signature; mismatches return `SIGNATURE_INVALID`.
   *
   * Without this option the verifier still produces a structurally
   * valid result, but it is only checking that the embedded key
   * is internally consistent with the signature — an attacker
   * could forge an entire record with their own key and pass that
   * check. Real callers should fetch the firm's public key from
   * `/.well-known/signing-key` (or pin it at deploy time) and
   * pass it here.
   */
  trustedPublicKey?: string;
}

// Buffer.from(s, 'base64') silently ignores invalid chars; strict
// validation keeps parity with the Python sibling's b64decode(..., validate=True).
const BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;

function isStrictBase64(value: string): boolean {
  return value.length % 4 === 0 && BASE64_PATTERN.test(value);
}

/** Parse SPKI DER bytes, returning `null` unless the key is ECDSA P-256. */
function loadP256PublicKey(spkiDer: Buffer): KeyObject | null {
  let keyObject: KeyObject;
  try {
    keyObject = createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
  } catch {
    return null;
  }
  if (keyObject.asymmetricKeyType !== 'ec') {
    return null;
  }
  const namedCurve = keyObject.asymmetricKeyDetails?.namedCurve;
  if (namedCurve !== 'prime256v1') {
    return null;
  }
  return keyObject;
}

/**
 * Verify the ECDSA signature on a single ledger record.
 *
 * Performs three checks:
 *
 *   1. Recomputes `chainHash` from `recordHash` and `previousHash`
 *      and asserts it matches what's on the record. This catches
 *      tampering with any of the three fields without needing the
 *      key.
 *   2. Optionally asserts the `publicKey` embedded on the record
 *      matches a caller-supplied trusted key (see
 *      {@link VerifySignatureOptions.trustedPublicKey}). When the
 *      option is omitted the verifier only checks the embedded
 *      key for self-consistency, which is a strictly weaker
 *      property.
 *   3. Loads the embedded `publicKey` as an ECDSA P-256 key
 *      (rejecting RSA, Ed25519, secp384r1, etc.) and verifies the
 *      base64 ECDSA signature over `chainHash`.
 *
 * All checks must pass for the result to be `valid: true`. The
 * `reason` field on a failure result identifies which check failed.
 *
 * The base64 fields (`signature`, `publicKey`) are validated
 * strictly — non-canonical or non-padded base64 is rejected as
 * `SIGNATURE_INVALID`, matching the strict-decoding behaviour of
 * the Python sibling.
 *
 * @param record - The record to verify.
 * @param options - Optional {@link VerifySignatureOptions}; in
 *   particular, pass `trustedPublicKey` to pin the firm's public
 *   key.
 * @returns A {@link SignatureVerificationResult}.
 */
export function verifySignature(
  record: LedgerRecordProjection,
  options: VerifySignatureOptions = {},
): SignatureVerificationResult {
  const expectedChainHash = computeChainHash(record.recordHash, record.previousHash);
  if (expectedChainHash !== record.chainHash) {
    return { valid: false, reason: ChainInvalidReason.HASH_MISMATCH };
  }

  if (!isStrictBase64(record.publicKey) || !isStrictBase64(record.signature)) {
    return { valid: false, reason: ChainInvalidReason.SIGNATURE_INVALID };
  }

  if (options.trustedPublicKey !== undefined && options.trustedPublicKey !== record.publicKey) {
    return { valid: false, reason: ChainInvalidReason.SIGNATURE_INVALID };
  }

  const keyObject = loadP256PublicKey(Buffer.from(record.publicKey, 'base64'));
  if (keyObject === null) {
    return { valid: false, reason: ChainInvalidReason.SIGNATURE_INVALID };
  }

  const signatureValid = verify(
    'sha256',
    Buffer.from(record.chainHash, 'utf8'),
    { key: keyObject, dsaEncoding: 'der' },
    Buffer.from(record.signature, 'base64'),
  );

  if (!signatureValid) {
    return { valid: false, reason: ChainInvalidReason.SIGNATURE_INVALID };
  }

  return { valid: true, reason: null };
}
