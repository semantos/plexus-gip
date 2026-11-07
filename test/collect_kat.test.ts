/**
 * The known-answer file for the holder's proofs at `POST /collect`,
 * test/fixtures/collect_kat.json, the plain collect and the extension to a new
 * place (decision 12).
 *
 * scripts/gen-collect-kat.ts writes it. Here it is regenerated and compared
 * byte for byte, its payloads are checked against ones written by hand, and
 * its request is sent to an office, which makes the child's vouch out to the
 * new key.
 */
import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { PrivateKey } from '@bsv/sdk';
import { COLLECT_KAT_PATH, buildCollectKat } from '../scripts/gen-collect-kat';
import { katKey } from '../scripts/gen-bodies-kat';
import { fromB64url, fromUtf8, isoSeconds, verifyJwtByKid } from '../src';
import { appPlace, placeKeyOf } from '../src/places';
import { Office, type OfficeState, type Store, initState, officeHandler, pickupProof } from '../bodies/office';

const text = readFileSync(COLLECT_KAT_PATH, 'utf8');
const KAT = JSON.parse(text);
const BODIES = JSON.parse(readFileSync(new URL('./fixtures/bodies_kat.json', import.meta.url), 'utf8'));

describe('collect known answers', () => {
  test('regenerating the file gives the same bytes', () => {
    expect(buildCollectKat()).toBe(text);
  });

  test('the held key is the bodies file\'s subject, and each proof is the hand-written one', () => {
    expect(KAT.keys.held.did).toBe(BODIES.parties.subject);
    const { held, new: fresh, guardian } = KAT.keys;
    expect(KAT.nonces).toEqual({ collect: 'collect', extend: `extend:${fresh.did}`, guardian: `guardian:${fresh.did}` });
    const want: Record<string, [string, string]> = {
      collect: [fresh.did, 'collect'],
      extend: [held.did, `extend:${fresh.did}`],
      guardian: [guardian.did, `guardian:${fresh.did}`],
    };
    for (const [name, [signer, nonce]] of Object.entries(want)) {
      const p = KAT.proofs[name];
      expect(p.header).toEqual({ alg: 'ES256K', typ: 'openid4vci-proof+jwt', kid: `${signer}#${signer.slice('did:key:'.length)}` });
      expect(p.payload).toEqual({ aud: 'did:web:hillside.example.edu.au', nonce, iat: KAT.at });
      // The key order is part of the bytes: aud, nonce, iat.
      expect(fromUtf8(fromB64url(p.jwt.split('.')[1]))).toBe(JSON.stringify({ aud: KAT.body, nonce, iat: KAT.at }));
      expect(verifyJwtByKid(p.jwt, 'openid4vci-proof+jwt')?.signer).toBe(signer);
    }
    expect(KAT.request.body).toEqual({ proof: KAT.proofs.collect.jwt, extend: KAT.proofs.extend.jwt, cosign: [KAT.proofs.guardian.jwt] });
  });

  test('an office takes the request: the child\'s vouch, made out to the new key', async () => {
    const place = appPlace('kids-world:gem-island');
    const child = placeKeyOf(katKey('holder/root'), place);
    const parent = placeKeyOf(katKey('guardian/root'), place);
    let clock = KAT.at - 3600;
    const { state, token } = initState({
      did: KAT.body,
      anchorSk: katKey('hillside/anchor'),
      stewardSk: katKey('steward'),
      kind: 'school',
      claims: ['member', 'guardian_of_member'],
      periodEnds: ['2026-12-31T23:59:59Z'],
      now: clock - 86400,
    });
    let saved: OfficeState = structuredClone(state);
    const store: Store = { load: () => structuredClone(saved), save: (s) => void (saved = structuredClone(s)) };
    const h = officeHandler(new Office(store, { now: () => clock }));
    const call = async (path: string, body: unknown, auth = false) => {
      const headers: Record<string, string> = { 'content-type': 'application/json', ...(auth && { authorization: `Bearer ${token}` }) };
      const res = await h(new Request(`https://hillside.example.edu.au${path}`, { method: 'POST', headers, body: JSON.stringify(body) }));
      return { status: res.status, json: (await res.json()) as any };
    };
    await call('/desk/roster', { rows: [{ id: 'c', kind: 'member', label: 'C' }, { id: 'g', kind: 'guardian', label: 'G', guardianOf: ['c'] }] }, true);
    await call('/desk/consent', { ids: ['c', 'g'], consent: true }, true);
    const v = await call('/desk/vouch', { ids: ['c', 'g'] }, true);
    for (const [p, sk] of [[v.json.pickups[0], child], [v.json.pickups[1], parent]] as [any, PrivateKey][]) {
      const code = p.url.slice(p.url.lastIndexOf('/') + 1);
      expect((await call(`/pickup/${code}`, { proof: pickupProof({ subjectSk: sk, body: KAT.body, code, at: clock }) })).status).toBe(200);
    }
    clock = KAT.at;
    const { cosign, ...adult } = KAT.request.body;
    expect((await call('/collect', adult)).json).toEqual({ error: 'guardian_required', detail: 'a child\'s new place needs a guardian\'s proof in cosign' });
    const r = await call(KAT.request.path, KAT.request.body);
    expect(r.status).toBe(200);
    expect(r.json.vouches).toHaveLength(1);
    const vouch = JSON.parse(fromUtf8(fromB64url(r.json.vouches[0].split('.')[1])));
    expect(vouch.credentialSubject).toEqual({ id: KAT.keys.new.did, member: true });
    expect(saved.vouches.at(-1)).toMatchObject({ rosterId: 'c', subject: KAT.keys.new.did, issuedAt: isoSeconds(KAT.at) });
    clock = KAT.at + 301;
    expect((await call(KAT.request.path, KAT.request.body)).json).toEqual({ error: 'stale' });
  });
});
