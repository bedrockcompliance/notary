/**
 * End-to-end certificate verification.
 *
 * @packageDocumentation
 */

import { verifySignature, type VerifySignatureOptions } from './signature';
import {
  type CertificateProjection,
  type CertificateVerificationResult,
  type LedgerRecordProjection,
} from './types';

/** Input to {@link verifyCertificate}. */
export interface VerifyCertificateInput {
  /** The certificate envelope. */
  certificate: CertificateProjection;
  /** The ledger record the certificate is anchored to. */
  record: LedgerRecordProjection;
}

/** Optional behaviour switches for {@link verifyCertificate}. */
export type VerifyCertificateOptions = VerifySignatureOptions;

/**
 * Verify a Bedrock certificate end-to-end.
 *
 * Delegates to {@link verifySignature} for the cryptographic check
 * and returns a structured result that includes the certificate and
 * record that were inspected — useful for displaying the verified
 * payload in a UI without re-fetching it.
 *
 * @param input - The certificate and its underlying record.
 * @returns A {@link CertificateVerificationResult}.
 *
 * @example
 * ```ts
 * const response = await fetch(
 *   `https://api.bedrockgovernance.com/v1/verify/${certificateId}`,
 * );
 * const { certificate, record } = await response.json();
 * const result = verifyCertificate({ certificate, record });
 * if (!result.valid) {
 *   throw new Error(`Certificate invalid: ${result.reason}`);
 * }
 * ```
 */
export function verifyCertificate(
  input: VerifyCertificateInput,
  options: VerifyCertificateOptions = {},
): CertificateVerificationResult {
  const { valid, reason } = verifySignature(input.record, options);
  return {
    valid,
    reason,
    certificate: input.certificate,
    record: input.record,
    verifiedAt: new Date().toISOString(),
  };
}
