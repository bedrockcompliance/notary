/**
 * Chain hash computation and full-chain verification.
 *
 * @packageDocumentation
 */

import { computeChainHash } from './hash';
import { computeRecordHash } from './record';
import { verifySignature } from './signature';
import {
  ChainInvalidReason,
  GENESIS_HASH,
  type ChainVerificationResult,
  type LedgerRecordProjection,
} from './types';

/**
 * Optional behaviour switches for {@link verifyChain}.
 */
export interface VerifyChainOptions {
  /**
   * Base64-encoded SPKI DER public keys the caller trusts as the
   * platform's own — the current signing key plus any retired keys
   * still needed to verify records signed before a rotation.
   *
   * When provided, each record's ECDSA signature is verified and
   * pinned to this set once its structural checks pass: a record
   * whose embedded key is not in the set, or whose signature does not
   * verify, fails with `SIGNATURE_INVALID`. This rejects a record
   * forged with its own key even though its hash chain is internally
   * consistent.
   *
   * Omit it to check chain structure only — callers who hold the
   * chain but not the key can still detect structural tampering.
   */
  trustedPublicKeys?: Iterable<string>;
}

/**
 * Verify the integrity of a sequence of Bedrock ledger records.
 *
 * The function walks the records in order and, at every position,
 * checks that:
 *
 *   1. When `payload` is present, the recomputed `recordHash` matches
 *      the stored `recordHash` (detects field-level tampering).
 *   2. The sequence number is exactly one greater than the previous
 *      record's (gaps and reorderings are detected).
 *   3. The `previousHash` matches the previous record's `chainHash`
 *      ({@link GENESIS_HASH} for the first record).
 *   4. The recomputed `chainHash` matches the stored `chainHash`
 *      (catches edits to either field).
 *
 * If any check fails, verification stops at that record and the
 * result identifies it. Signature verification is skipped by default
 * so that callers who only have the chain (without the public key)
 * can still detect tampering in the structure; pass
 * {@link VerifyChainOptions.trustedPublicKeys} to additionally verify
 * and pin every record's signature.
 *
 * @param records - The records to verify, ordered by `sequenceNumber`
 *   ascending and starting from the firm's genesis record (the
 *   first record's `previousHash` must equal {@link GENESIS_HASH}).
 *   Pass an empty array to get a trivially valid result. Verifying
 *   a mid-chain slice is not currently supported.
 * @param firmId - Firm identifier echoed back on the result. Not
 *   compared against the records themselves.
 * @param options - Optional {@link VerifyChainOptions}; pass
 *   `trustedPublicKeys` to pin signatures against the platform's keys.
 * @returns A {@link ChainVerificationResult} describing the outcome.
 */
export function verifyChain(
  records: readonly LedgerRecordProjection[],
  firmId: string,
  options: VerifyChainOptions = {},
): ChainVerificationResult {
  const verifiedAt = new Date().toISOString();
  const trustedPublicKeys =
    options.trustedPublicKeys !== undefined ? new Set(options.trustedPublicKeys) : null;

  if (records.length === 0) {
    return {
      firmId,
      verifiedAt,
      totalRecords: 0,
      isValid: true,
      firstInvalidRecordId: null,
      firstInvalidSequenceNumber: null,
      invalidReason: null,
    };
  }

  for (let i = 0; i < records.length; i++) {
    const record = records[i] as LedgerRecordProjection;
    const previousRecord = i > 0 ? (records[i - 1] as LedgerRecordProjection) : null;
    const expectedPreviousHash = previousRecord ? previousRecord.chainHash : GENESIS_HASH;

    if (record.payload !== undefined) {
      let recomputed: string;
      try {
        recomputed = computeRecordHash(record.payload);
      } catch {
        return failure(records, firmId, verifiedAt, record, ChainInvalidReason.HASH_MISMATCH);
      }
      if (recomputed !== record.recordHash) {
        return failure(records, firmId, verifiedAt, record, ChainInvalidReason.HASH_MISMATCH);
      }
    }

    if (previousRecord && record.sequenceNumber !== previousRecord.sequenceNumber + 1) {
      return failure(records, firmId, verifiedAt, record, ChainInvalidReason.SEQUENCE_GAP);
    }

    if (record.previousHash !== expectedPreviousHash) {
      return failure(
        records,
        firmId,
        verifiedAt,
        record,
        ChainInvalidReason.PREVIOUS_HASH_MISMATCH,
      );
    }

    const expectedChainHash = computeChainHash(record.recordHash, record.previousHash);
    if (record.chainHash !== expectedChainHash) {
      return failure(records, firmId, verifiedAt, record, ChainInvalidReason.HASH_MISMATCH);
    }

    if (trustedPublicKeys !== null) {
      if (!trustedPublicKeys.has(record.publicKey)) {
        return failure(records, firmId, verifiedAt, record, ChainInvalidReason.SIGNATURE_INVALID);
      }
      if (!verifySignature(record, { trustedPublicKey: record.publicKey }).valid) {
        return failure(records, firmId, verifiedAt, record, ChainInvalidReason.SIGNATURE_INVALID);
      }
    }
  }

  return {
    firmId,
    verifiedAt,
    totalRecords: records.length,
    isValid: true,
    firstInvalidRecordId: null,
    firstInvalidSequenceNumber: null,
    invalidReason: null,
  };
}

/** Build a structured failure result for {@link verifyChain}. */
function failure(
  records: readonly LedgerRecordProjection[],
  firmId: string,
  verifiedAt: string,
  record: LedgerRecordProjection,
  reason: ChainInvalidReason,
): ChainVerificationResult {
  return {
    firmId,
    verifiedAt,
    totalRecords: records.length,
    isValid: false,
    firstInvalidRecordId: record.id,
    firstInvalidSequenceNumber: record.sequenceNumber,
    invalidReason: reason,
  };
}
