/**
 * The known-answer file for `src/bodies/`, test/fixtures/bodies_kat.json.
 *
 * scripts/gen-bodies-kat.ts writes it from fixed keys and times. Here it is
 * regenerated and compared byte for byte, and its verdict is checked against
 * one written by hand, so a generator bug cannot commit a wrong answer.
 */
import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { buildBodiesKat, KAT_PATH } from '../scripts/gen-bodies-kat';
import {
  type BodyVerdict,
  hex,
  publicKeyFromDidKey,
  readDelegation,
  readRegistryEntry,
  verifyJwtByKid,
  verifyPresentation,
} from '../src';

const text = readFileSync(KAT_PATH, 'utf8');
const KAT = JSON.parse(text);

describe('bodies known answers', () => {
  test('regenerating the file gives the same bytes', () => {
    expect(buildBodiesKat()).toBe(text);
  });

  test('the expected verdict is the hand-written one, and the code computes it', () => {
    const expected: BodyVerdict = {
      ok: true,
      body: { did: 'did:web:hillside.example.edu.au', kind: 'school' },
      claim: 'member',
      subject: KAT.parties.subject,
    };
    expect(KAT.verify.result).toEqual(expected);
    const o = KAT.verify.options;
    const got = verifyPresentation(KAT.presentation, {
      ...o,
      stewards: new Set(o.stewards),
      registryEntries: [KAT.registryEntry],
      statusLists: { [KAT.statusList.url]: KAT.statusList.jwt },
    });
    expect(got).toEqual(expected);
  });

  test('each piece reads back on its own', () => {
    expect(readRegistryEntry(KAT.registryEntry)?.steward).toBe(KAT.parties.steward);
    expect(readDelegation(KAT.delegation)).toEqual({
      anchor: KAT.parties.anchor,
      node: hex(publicKeyFromDidKey(KAT.parties.node)),
      purpose: 'body.vouch',
    });
    expect(verifyJwtByKid(KAT.vouch)?.signer).toBe(KAT.parties.node);
    expect(verifyJwtByKid(KAT.statusList.jwt)?.signer).toBe(KAT.parties.node);
    expect(verifyJwtByKid(KAT.presentation, 'vp+jwt')?.signer).toBe(KAT.parties.subject);
  });
});
