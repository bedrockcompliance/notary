/**
 * SHA-256 helpers (lower-case hex output).
 *
 * @packageDocumentation
 */

import { createHash } from 'node:crypto';

/**
 * Compute the SHA-256 hash of a UTF-8 string.
 *
 * @param input - The string to hash.
 * @returns Lower-case hex digest (64 characters).
 *
 * @example
 * ```ts
 * sha256('hello');
 * // → '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
 * ```
 */
export function sha256(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/**
 * Compute the SHA-256 hash of a binary buffer.
 *
 * @param buffer - The bytes to hash.
 * @returns Lower-case hex digest (64 characters).
 */
export function sha256Buffer(buffer: Buffer): string {
  return createHash('sha256').update(buffer).digest('hex');
}

/**
 * Compute the chain hash for a record.
 *
 * @param recordHash - SHA-256 of the canonical JSON of the record's
 *   payload.
 * @param previousHash - The previous record's `chainHash`, or the
 *   genesis hash for the first record on the chain.
 * @returns Lower-case hex SHA-256 of `recordHash || previousHash`.
 *
 * @example
 * ```ts
 * const chainHash = computeChainHash(
 *   sha256(canonicalise(payload)),
 *   GENESIS_HASH,
 * );
 * ```
 */
export function computeChainHash(recordHash: string, previousHash: string): string {
  return sha256(recordHash + previousHash);
}
