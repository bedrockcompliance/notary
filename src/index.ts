/**
 * `@bedrockgovernance/notary` -- open verifier and canonical-form
 * library for the Bedrock immutable advice ledger.
 *
 * @packageDocumentation
 */

export { canonicalise } from './canonicalise';
export { sha256, sha256Buffer, computeChainHash } from './hash';
export { verifyChain, type VerifyChainOptions } from './chain';
export { computeRecordHash } from './record';
export { verifySignature } from './signature';
export { verifyCertificate, type VerifyCertificateInput } from './certificate';

export {
  ChainInvalidReason,
  GENESIS_HASH,
  SIGNING_ALGORITHM,
  type CertificateProjection,
  type CertificateVerificationResult,
  type ChainVerificationResult,
  type LedgerRecordProjection,
  type SignatureVerificationResult,
  type RecordPayload,
  type Signer,
} from './types';
