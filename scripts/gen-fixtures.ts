/**
 * Generate the shared cross-language fixture corpus.
 *
 * Run with `pnpm --filter @bedrockgovernance/notary gen:fixtures`.
 */

import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalise } from '../src/canonicalise';
import { computeChainHash, sha256 } from '../src/hash';
import { computeRecordHash } from '../src/record';
import { GENESIS_HASH } from '../src/types';

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, '..', 'fixtures');

interface CanonicaliseFixture {
  name: string;
  input: unknown;
  expected: string;
}

/** Assert non-undefined result for fixture inputs. */
function canon(value: unknown): string {
  const result = canonicalise(value);
  if (result === undefined) {
    throw new Error('canonicalise returned undefined for a fixture input');
  }
  return result;
}

const canonicaliseCases: CanonicaliseFixture[] = [
  { name: 'empty-object', input: {}, expected: canon({}) },
  { name: 'sorted-keys', input: { z: 1, a: 2, m: 3 }, expected: canon({ z: 1, a: 2, m: 3 }) },
  {
    name: 'nested-objects',
    input: { b: { d: 1, c: 2 }, a: { f: 3, e: 4 } },
    expected: canon({ b: { d: 1, c: 2 }, a: { f: 3, e: 4 } }),
  },
  { name: 'array-order-preserved', input: { arr: [3, 1, 2] }, expected: canon({ arr: [3, 1, 2] }) },
  {
    name: 'unicode-and-emoji',
    input: { emoji: '🔐', text: 'héllo' },
    expected: canon({ emoji: '🔐', text: 'héllo' }),
  },
  {
    name: 'line-and-paragraph-separators-preserved-literally',
    input: { text: 'line1\u2028line2\u2029line3' },
    expected: canon({ text: 'line1\u2028line2\u2029line3' }),
  },
  {
    name: 'numbers',
    input: { zero: 0, negative: -42, float: 3.14 },
    expected: canon({ zero: 0, negative: -42, float: 3.14 }),
  },
  { name: 'null-value', input: { value: null }, expected: canon({ value: null }) },
  { name: 'booleans', input: { yes: true, no: false }, expected: canon({ yes: true, no: false }) },
  { name: 'top-level-null', input: null, expected: canon(null) },
  { name: 'top-level-string', input: 'hello', expected: canon('hello') },
  { name: 'top-level-number', input: 42, expected: canon(42) },
  { name: 'top-level-array', input: [1, 2, 3], expected: canon([1, 2, 3]) },
  {
    name: 'array-of-objects',
    input: [
      { b: 1, a: 2 },
      { d: 3, c: 4 },
    ],
    expected: canon([
      { b: 1, a: 2 },
      { d: 3, c: 4 },
    ]),
  },
  {
    name: 'realistic-ledger-payload',
    input: {
      firmId: '01HW1AAAAA',
      sequenceNumber: 1,
      eventType: 'DOCUMENT_SUBMITTED',
      actorId: '01HW2BBBBB',
      actorFcaRef: null,
      actorName: 'Test Firm',
      documentHash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      documentMetadata: {
        documentReference: 'SR-2026-0142',
        documentType: 'SUITABILITY_REPORT',
      },
      previousHash: '0'.repeat(64),
      timestamp: '2026-04-09T00:00:00.000Z',
      reviewJobId: null,
    },
    expected: canon({
      firmId: '01HW1AAAAA',
      sequenceNumber: 1,
      eventType: 'DOCUMENT_SUBMITTED',
      actorId: '01HW2BBBBB',
      actorFcaRef: null,
      actorName: 'Test Firm',
      documentHash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      documentMetadata: {
        documentReference: 'SR-2026-0142',
        documentType: 'SUITABILITY_REPORT',
      },
      previousHash: '0'.repeat(64),
      timestamp: '2026-04-09T00:00:00.000Z',
      reviewJobId: null,
    }),
  },
];

interface HashFixture {
  input: string;
  expected: string;
}

const hashCases: HashFixture[] = [
  { input: '', expected: sha256('') },
  { input: 'hello', expected: sha256('hello') },
  { input: 'héllo 🔐', expected: sha256('héllo 🔐') },
  { input: 'a'.repeat(1024), expected: sha256('a'.repeat(1024)) },
];

interface RecordHashFixture {
  name: string;
  payload: Record<string, unknown>;
  expected: string;
}

const recordHashCases: RecordHashFixture[] = canonicaliseCases
  .filter((c): c is CanonicaliseFixture & { input: Record<string, unknown> } =>
    typeof c.input === 'object' && c.input !== null && !Array.isArray(c.input),
  )
  .map((c) => ({
    name: c.name,
    payload: c.input,
    expected: computeRecordHash(c.input),
  }));

interface ChainFixture {
  name: string;
  recordHash: string;
  previousHash: string;
  expected: string;
}

const chainCases: ChainFixture[] = [
  {
    name: 'genesis',
    recordHash: sha256('record-1'),
    previousHash: GENESIS_HASH,
    expected: computeChainHash(sha256('record-1'), GENESIS_HASH),
  },
  {
    name: 'second-record',
    recordHash: sha256('record-2'),
    previousHash: sha256('previous-chain-hash'),
    expected: computeChainHash(sha256('record-2'), sha256('previous-chain-hash')),
  },
];

function writeJson(file: string, value: unknown): void {
  writeFileSync(join(outDir, file), `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

writeJson('canonicalise.json', { cases: canonicaliseCases });
writeJson('hash.json', { cases: hashCases });
writeJson('record-hash.json', { cases: recordHashCases });
writeJson('chain.json', { cases: chainCases, genesisHash: GENESIS_HASH });

// eslint-disable-next-line no-console
console.log(
  `Wrote ${canonicaliseCases.length} canonicalise, ${hashCases.length} hash, ${recordHashCases.length} record-hash, ${chainCases.length} chain cases to ${outDir}`,
);
