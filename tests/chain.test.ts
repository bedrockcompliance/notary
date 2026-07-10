import { generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { describe, it, expect } from 'vitest';

import { verifyChain } from '../src/chain';
import { computeChainHash, sha256 } from '../src/hash';
import { computeRecordHash } from '../src/record';
import { ChainInvalidReason, GENESIS_HASH, type LedgerRecordProjection } from '../src/types';

const FIRM_ID = 'test-firm-id';

function buildChainRecords(count: number): LedgerRecordProjection[] {
  const records: LedgerRecordProjection[] = [];

  for (let i = 0; i < count; i++) {
    const previousHash = i === 0 ? GENESIS_HASH : (records[i - 1] as LedgerRecordProjection).chainHash;
    const payload = {
      firmId: FIRM_ID,
      sequenceNumber: i + 1,
      eventType: 'DOCUMENT_SUBMITTED',
      actorId: 'actor-1',
      actorFcaRef: null,
      actorName: 'Test Actor',
      documentHash: sha256(`document-${i}`),
      documentMetadata: {},
      previousHash,
      timestamp: '2026-04-09T00:00:00.000Z',
      reviewJobId: null,
    };
    const recordHash = computeRecordHash(payload);
    const chainHash = computeChainHash(recordHash, previousHash);

    records.push({
      id: `record-${i + 1}`,
      sequenceNumber: i + 1,
      recordHash,
      chainHash,
      previousHash,
      signature: 'placeholder-signature',
      publicKey: 'placeholder-public-key',
      payload,
    });
  }

  return records;
}

interface KeyPair {
  privateKey: KeyObject;
  publicKeyBase64: string;
}

function generateKey(): KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    privateKey,
    publicKeyBase64: Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).toString('base64'),
  };
}

/** Build a real, signed chain of `count` records signed by `keys`. */
function signedChain(keys: KeyPair, count: number): LedgerRecordProjection[] {
  const records: LedgerRecordProjection[] = [];
  for (let i = 0; i < count; i++) {
    const previousHash = i === 0 ? GENESIS_HASH : (records[i - 1] as LedgerRecordProjection).chainHash;
    const payload = {
      firmId: FIRM_ID,
      sequenceNumber: i + 1,
      eventType: 'DOCUMENT_SUBMITTED',
      actorId: 'actor-1',
      actorFcaRef: null,
      actorName: 'Test Actor',
      documentHash: sha256(`document-${i}`),
      documentMetadata: {},
      previousHash,
      timestamp: '2026-04-09T00:00:00.000Z',
      reviewJobId: null,
    };
    const recordHash = computeRecordHash(payload);
    const chainHash = computeChainHash(recordHash, previousHash);
    const signature = sign('sha256', Buffer.from(chainHash, 'utf8'), {
      key: keys.privateKey,
      dsaEncoding: 'der',
    }).toString('base64');
    records.push({
      id: `record-${i + 1}`,
      sequenceNumber: i + 1,
      recordHash,
      chainHash,
      previousHash,
      signature,
      publicKey: keys.publicKeyBase64,
      payload,
    });
  }
  return records;
}

describe('GENESIS_HASH', () => {
  it('is 64 zero characters', () => {
    expect(GENESIS_HASH).toBe('0'.repeat(64));
  });
});

describe('computeChainHash', () => {
  it('produces SHA-256 of recordHash + previousHash', () => {
    const recordHash = sha256('record');
    const previousHash = GENESIS_HASH;
    expect(computeChainHash(recordHash, previousHash)).toBe(sha256(recordHash + previousHash));
  });

  it('is deterministic', () => {
    expect(computeChainHash('abc', 'def')).toBe(computeChainHash('abc', 'def'));
  });

  it('changes when recordHash changes', () => {
    expect(computeChainHash('hash1', GENESIS_HASH)).not.toBe(
      computeChainHash('hash2', GENESIS_HASH),
    );
  });

  it('changes when previousHash changes', () => {
    expect(computeChainHash('hash1', 'prev1')).not.toBe(computeChainHash('hash1', 'prev2'));
  });
});

describe('verifyChain', () => {
  it('returns valid for empty chain', () => {
    const result = verifyChain([], FIRM_ID);
    expect(result.isValid).toBe(true);
    expect(result.totalRecords).toBe(0);
    expect(result.firmId).toBe(FIRM_ID);
    expect(result.firstInvalidRecordId).toBeNull();
    expect(result.firstInvalidSequenceNumber).toBeNull();
    expect(result.invalidReason).toBeNull();
  });

  it('returns valid for single-record chain (genesis)', () => {
    const records = buildChainRecords(1);
    const result = verifyChain(records, FIRM_ID);
    expect(result.isValid).toBe(true);
    expect(result.totalRecords).toBe(1);
  });

  it('returns valid for chain of 100 records', () => {
    const records = buildChainRecords(100);
    const result = verifyChain(records, FIRM_ID);
    expect(result.isValid).toBe(true);
    expect(result.totalRecords).toBe(100);
  });

  it('detects tampered recordHash at record 50', () => {
    const records = buildChainRecords(100);
    (records[49] as LedgerRecordProjection).recordHash = sha256('tampered');
    const result = verifyChain(records, FIRM_ID);
    expect(result.isValid).toBe(false);
    expect(result.firstInvalidSequenceNumber).toBe(50);
    expect(result.invalidReason).toBe(ChainInvalidReason.HASH_MISMATCH);
  });

  it('detects tampered chainHash at record 50', () => {
    const records = buildChainRecords(100);
    (records[49] as LedgerRecordProjection).chainHash = sha256('tampered');
    const result = verifyChain(records, FIRM_ID);
    expect(result.isValid).toBe(false);
    expect(result.firstInvalidSequenceNumber).toBe(50);
    expect(result.invalidReason).toBe(ChainInvalidReason.HASH_MISMATCH);
  });

  it('detects sequence gap when record 50 is removed', () => {
    const records = buildChainRecords(100);
    records.splice(49, 1);
    const result = verifyChain(records, FIRM_ID);
    expect(result.isValid).toBe(false);
    expect(result.firstInvalidSequenceNumber).toBe(51);
    expect(result.invalidReason).toBe(ChainInvalidReason.SEQUENCE_GAP);
  });

  it('detects an injected record between 50 and 51', () => {
    const records = buildChainRecords(100);
    const baseChainHash = (records[49] as LedgerRecordProjection).chainHash;
    const injectedRecordHash = sha256('injected');
    const injected: LedgerRecordProjection = {
      id: 'injected',
      sequenceNumber: 51,
      recordHash: injectedRecordHash,
      chainHash: computeChainHash(injectedRecordHash, baseChainHash),
      previousHash: baseChainHash,
      signature: 'fake',
      publicKey: 'fake',
    };
    for (let i = 50; i < records.length; i++) {
      (records[i] as LedgerRecordProjection).sequenceNumber += 1;
    }
    records.splice(50, 0, injected);
    const result = verifyChain(records, FIRM_ID);
    expect(result.isValid).toBe(false);
    expect(result.invalidReason).toBe(ChainInvalidReason.PREVIOUS_HASH_MISMATCH);
  });

  it('detects wrong previousHash on the first record', () => {
    const records = buildChainRecords(1);
    (records[0] as LedgerRecordProjection).previousHash = sha256('wrong');
    const result = verifyChain(records, FIRM_ID);
    expect(result.isValid).toBe(false);
    expect(result.firstInvalidSequenceNumber).toBe(1);
    expect(result.invalidReason).toBe(ChainInvalidReason.PREVIOUS_HASH_MISMATCH);
  });

  it('detects tampered payload field', () => {
    const records = buildChainRecords(5);
    records[2]!.payload = { ...records[2]!.payload!, documentMetadata: { tampered: true } };
    const result = verifyChain(records, FIRM_ID);
    expect(result.isValid).toBe(false);
    expect(result.firstInvalidSequenceNumber).toBe(3);
    expect(result.invalidReason).toBe(ChainInvalidReason.HASH_MISMATCH);
  });

  it('detects tampered actorName in payload', () => {
    const records = buildChainRecords(3);
    records[1]!.payload = { ...records[1]!.payload!, actorName: 'Tampered' };
    const result = verifyChain(records, FIRM_ID);
    expect(result.isValid).toBe(false);
    expect(result.firstInvalidSequenceNumber).toBe(2);
    expect(result.invalidReason).toBe(ChainInvalidReason.HASH_MISMATCH);
  });

  it('skips record hash recomputation when payload absent', () => {
    const records = buildChainRecords(3).map(({ payload, ...rest }) => rest);
    const result = verifyChain(records, FIRM_ID);
    expect(result.isValid).toBe(true);
  });

  it('detects previousHash mismatch on projection-only records', () => {
    const records = buildChainRecords(3).map(({ payload, ...rest }) => rest);
    records[1]!.previousHash = sha256('wrong');
    const result = verifyChain(records, FIRM_ID);
    expect(result.isValid).toBe(false);
    expect(result.invalidReason).toBe(ChainInvalidReason.PREVIOUS_HASH_MISMATCH);
  });

  it('treats malformed payload as HASH_MISMATCH instead of throwing', () => {
    const records = buildChainRecords(1);
    const circular = {} as Record<string, unknown>;
    circular.self = circular;
    records[0]!.payload = circular;
    const result = verifyChain(records, FIRM_ID);
    expect(result.isValid).toBe(false);
    expect(result.invalidReason).toBe(ChainInvalidReason.HASH_MISMATCH);
  });

  it('passes a genuine chain when its key is trusted', () => {
    const keys = generateKey();
    const records = signedChain(keys, 3);
    const result = verifyChain(records, FIRM_ID, {
      trustedPublicKeys: [keys.publicKeyBase64],
    });
    expect(result.isValid).toBe(true);
    expect(result.totalRecords).toBe(3);
  });

  it('accepts a chain signed with a retired key still in the trusted set', () => {
    const retired = generateKey();
    const current = generateKey();
    const records = signedChain(retired, 2);
    const result = verifyChain(records, FIRM_ID, {
      trustedPublicKeys: [current.publicKeyBase64, retired.publicKeyBase64],
    });
    expect(result.isValid).toBe(true);
  });

  it('rejects a structurally sound record whose key is not trusted', () => {
    const keys = generateKey();
    const records = signedChain(keys, 2);
    const result = verifyChain(records, FIRM_ID, {
      trustedPublicKeys: [generateKey().publicKeyBase64],
    });
    expect(result.isValid).toBe(false);
    expect(result.invalidReason).toBe(ChainInvalidReason.SIGNATURE_INVALID);
    expect(result.firstInvalidSequenceNumber).toBe(1);
  });

  it('rejects a trusted key whose signature does not verify', () => {
    const keys = generateKey();
    const records = signedChain(keys, 1);
    // Swap in a signature over different bytes, keeping the (trusted)
    // key and the chain structure intact.
    (records[0] as LedgerRecordProjection).signature = sign(
      'sha256',
      Buffer.from('different bytes', 'utf8'),
      { key: keys.privateKey, dsaEncoding: 'der' },
    ).toString('base64');
    const result = verifyChain(records, FIRM_ID, {
      trustedPublicKeys: [keys.publicKeyBase64],
    });
    expect(result.isValid).toBe(false);
    expect(result.invalidReason).toBe(ChainInvalidReason.SIGNATURE_INVALID);
  });

  it('reports a structural failure before checking signatures', () => {
    const keys = generateKey();
    const records = signedChain(keys, 2);
    (records[1] as LedgerRecordProjection).payload = {
      ...(records[1] as LedgerRecordProjection).payload!,
      actorName: 'Tampered',
    };
    const result = verifyChain(records, FIRM_ID, {
      trustedPublicKeys: [keys.publicKeyBase64],
    });
    expect(result.isValid).toBe(false);
    expect(result.invalidReason).toBe(ChainInvalidReason.HASH_MISMATCH);
  });

  it('skips signature checks entirely when no trusted keys are given', () => {
    // Forged record with a self-consistent but untrusted key still
    // passes when the option is omitted (structure-only, default).
    const forged = generateKey();
    const records = signedChain(forged, 1);
    expect(verifyChain(records, FIRM_ID).isValid).toBe(true);
  });
});
