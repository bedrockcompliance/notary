import { generateKeyPairSync, sign } from 'node:crypto';
import { describe, it, expect } from 'vitest';

import { verifyCertificate } from '../src/certificate';
import { computeChainHash, sha256 } from '../src/hash';
import {
  ChainInvalidReason,
  GENESIS_HASH,
  type CertificateProjection,
  type LedgerRecordProjection,
} from '../src/types';

function buildSignedRecord(): { record: LedgerRecordProjection; certificate: CertificateProjection } {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicKeyBase64 = Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).toString(
    'base64',
  );
  const recordHash = sha256('record-payload');
  const previousHash = GENESIS_HASH;
  const chainHash = computeChainHash(recordHash, previousHash);
  const signature = sign('sha256', Buffer.from(chainHash, 'utf8'), {
    key: privateKey,
    dsaEncoding: 'der',
  }).toString('base64');

  return {
    record: {
      id: 'record-1',
      sequenceNumber: 1,
      recordHash,
      chainHash,
      previousHash,
      signature,
      publicKey: publicKeyBase64,
    },
    certificate: {
      id: 'cert-1',
      firmName: 'Apex Wealth Management',
      firmFrnNumber: '123456',
      issuedAt: '2026-04-09T12:00:00.000Z',
      metadata: { eventLabel: 'Review approved' },
    },
  };
}

describe('verifyCertificate', () => {
  it('returns valid for a correctly signed record', () => {
    const { record, certificate } = buildSignedRecord();
    const result = verifyCertificate({ certificate, record });
    expect(result.valid).toBe(true);
    expect(result.reason).toBeNull();
    expect(result.certificate).toBe(certificate);
    expect(result.record).toBe(record);
    expect(result.verifiedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('returns the failure reason from the underlying signature check', () => {
    const { record, certificate } = buildSignedRecord();
    record.chainHash = sha256('tampered');
    const result = verifyCertificate({ certificate, record });
    expect(result.valid).toBe(false);
    expect(result.reason).toBe(ChainInvalidReason.HASH_MISMATCH);
  });
});
