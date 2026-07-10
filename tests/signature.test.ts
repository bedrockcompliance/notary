import { generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { describe, it, expect, beforeAll } from 'vitest';

import { computeChainHash, sha256 } from '../src/hash';
import { verifySignature } from '../src/signature';
import { ChainInvalidReason, GENESIS_HASH, type LedgerRecordProjection } from '../src/types';

interface KeyPair {
  privateKey: KeyObject;
  publicKeyBase64: string;
}

function generateKey(): KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
  return {
    privateKey,
    publicKeyBase64: Buffer.from(publicKeyDer).toString('base64'),
  };
}

function signedRecord(keys: KeyPair, overrides: Partial<LedgerRecordProjection> = {}): LedgerRecordProjection {
  const recordHash = sha256('payload');
  const previousHash = GENESIS_HASH;
  const chainHash = computeChainHash(recordHash, previousHash);
  const signature = sign('sha256', Buffer.from(chainHash, 'utf8'), {
    key: keys.privateKey,
    dsaEncoding: 'der',
  }).toString('base64');
  return {
    id: 'record-1',
    sequenceNumber: 1,
    recordHash,
    chainHash,
    previousHash,
    signature,
    publicKey: keys.publicKeyBase64,
    ...overrides,
  };
}

let keys: KeyPair;

beforeAll(() => {
  keys = generateKey();
});

describe('verifySignature', () => {
  it('returns valid for a correctly signed record', () => {
    const record = signedRecord(keys);
    expect(verifySignature(record)).toEqual({ valid: true, reason: null });
  });

  it('returns HASH_MISMATCH when chainHash does not match recomputed value', () => {
    const record = signedRecord(keys, { chainHash: sha256('tampered') });
    expect(verifySignature(record)).toEqual({
      valid: false,
      reason: ChainInvalidReason.HASH_MISMATCH,
    });
  });

  it('returns SIGNATURE_INVALID for a wrong signature', () => {
    const otherKeys = generateKey();
    const tamperedSignature = sign('sha256', Buffer.from('something else', 'utf8'), {
      key: otherKeys.privateKey,
      dsaEncoding: 'der',
    }).toString('base64');
    const record = signedRecord(keys, { signature: tamperedSignature });
    expect(verifySignature(record)).toEqual({
      valid: false,
      reason: ChainInvalidReason.SIGNATURE_INVALID,
    });
  });

  it('returns SIGNATURE_INVALID when the public key does not match the signer', () => {
    const otherKeys = generateKey();
    const record = signedRecord(keys, { publicKey: otherKeys.publicKeyBase64 });
    expect(verifySignature(record)).toEqual({
      valid: false,
      reason: ChainInvalidReason.SIGNATURE_INVALID,
    });
  });

  it('returns SIGNATURE_INVALID when the public key is malformed', () => {
    const record = signedRecord(keys, { publicKey: 'not-base64-spki-der' });
    expect(verifySignature(record)).toEqual({
      valid: false,
      reason: ChainInvalidReason.SIGNATURE_INVALID,
    });
  });

  it('returns SIGNATURE_INVALID for non-canonical base64 in publicKey', () => {
    // `?` is outside the base64 alphabet. The permissive
    // `Buffer.from(s, "base64")` strips it silently; the strict
    // validator catches it before node:crypto sees the bytes.
    const record = signedRecord(keys, { publicKey: 'AB?C====' });
    expect(verifySignature(record)).toEqual({
      valid: false,
      reason: ChainInvalidReason.SIGNATURE_INVALID,
    });
  });

  it('returns SIGNATURE_INVALID for badly-padded base64 in signature', () => {
    // Length 7 — not a multiple of 4, so the strict validator
    // rejects it.
    const record = signedRecord(keys, { signature: 'AAAAAAA' });
    expect(verifySignature(record)).toEqual({
      valid: false,
      reason: ChainInvalidReason.SIGNATURE_INVALID,
    });
  });

  it('returns SIGNATURE_INVALID for valid base64 that does not decode to a P-256 SPKI key', () => {
    // Valid base64, but the bytes are not a SPKI-encoded ECDSA
    // key — `createPublicKey` rejects it.
    const record = signedRecord(keys, { publicKey: 'AAAA' });
    expect(verifySignature(record)).toEqual({
      valid: false,
      reason: ChainInvalidReason.SIGNATURE_INVALID,
    });
  });

  it('rejects RSA keys', async () => {
    const { generateKeyPairSync, sign: nodeSign } = await import('node:crypto');
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const rsaPublicB64 = Buffer.from(
      publicKey.export({ type: 'spki', format: 'der' }),
    ).toString('base64');

    const recordHash = sha256('payload');
    const previousHash = GENESIS_HASH;
    const chainHash = computeChainHash(recordHash, previousHash);
    const signature = nodeSign('sha256', Buffer.from(chainHash, 'utf8'), {
      key: privateKey,
    }).toString('base64');

    const record: LedgerRecordProjection = {
      id: 'rsa-record',
      sequenceNumber: 1,
      recordHash,
      chainHash,
      previousHash,
      signature,
      publicKey: rsaPublicB64,
    };
    expect(verifySignature(record)).toEqual({
      valid: false,
      reason: ChainInvalidReason.SIGNATURE_INVALID,
    });
  });

  it('rejects EC keys on a curve other than P-256', async () => {
    const { generateKeyPairSync } = await import('node:crypto');
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
    const otherCurveB64 = Buffer.from(
      publicKey.export({ type: 'spki', format: 'der' }),
    ).toString('base64');
    const record = signedRecord(keys, { publicKey: otherCurveB64 });
    expect(verifySignature(record)).toEqual({
      valid: false,
      reason: ChainInvalidReason.SIGNATURE_INVALID,
    });
  });

  it('returns valid when the trustedPublicKey option matches', () => {
    const record = signedRecord(keys);
    expect(
      verifySignature(record, { trustedPublicKey: keys.publicKeyBase64 }),
    ).toEqual({ valid: true, reason: null });
  });

  it('returns SIGNATURE_INVALID when the trustedPublicKey option does not match', () => {
    const record = signedRecord(keys);
    const otherKeys = generateKey();
    expect(
      verifySignature(record, { trustedPublicKey: otherKeys.publicKeyBase64 }),
    ).toEqual({ valid: false, reason: ChainInvalidReason.SIGNATURE_INVALID });
  });
});
