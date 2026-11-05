/**
 * The known-answer file for `src/bodies/`, test/fixtures/bodies_kat.json.
 *
 * scripts/gen-bodies-kat.ts writes it from fixed keys and times. Here it is
 * regenerated and compared byte for byte, and its verdict is checked against
 * one written by hand, so a generator bug cannot commit a wrong answer.
 */
import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { buildBodiesKat, KAT_PATH, katKey } from '../scripts/gen-bodies-kat';
import {
  type BodyVerdict,
  fromB64url,
  fromUtf8,
  hex,
  issueStatusList,
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
    expect(KAT.statusList.delegations.map(readDelegation)).toEqual(
      [KAT.parties.listNode, KAT.parties.node].map((n) => ({
        anchor: KAT.parties.anchor,
        node: hex(publicKeyFromDidKey(n)),
        purpose: 'body.vouch',
      })),
    );
    const vouch = verifyJwtByKid(KAT.vouch);
    expect(vouch?.signer).toBe(KAT.parties.node);
    expect(vouch?.payload).not.toHaveProperty('evidence');
    const list = verifyJwtByKid(KAT.statusList.jwt);
    expect(list?.signer).toBe(KAT.parties.listNode);
    expect(list?.payload.evidence).toEqual(
      KAT.statusList.delegations.map((delegation: unknown) => ({ type: 'SigningNodeDelegation', delegation })),
    );
    expect(verifyJwtByKid(KAT.presentation, 'vp+jwt')?.signer).toBe(KAT.parties.subject);
  });

  test('with node-1\'s delegation off the list, the same vouch is node_not_delegated', () => {
    const o = KAT.verify.options;
    const p = JSON.parse(fromUtf8(fromB64url(KAT.statusList.jwt.split('.')[1])));
    const retired = issueStatusList(katKey('hillside/node-2'), {
      issuer: p.issuer,
      delegations: KAT.statusList.delegations.slice(0, 1),
      url: KAT.statusList.url,
      revoked: KAT.statusList.revoked,
      validFrom: p.validFrom,
    });
    const got = verifyPresentation(KAT.presentation, {
      ...o,
      stewards: new Set(o.stewards),
      registryEntries: [KAT.registryEntry],
      statusLists: { [KAT.statusList.url]: retired },
    });
    expect(got).toEqual({ ok: false, reason: 'node_not_delegated' });
  });
});
