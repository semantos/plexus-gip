/**
 * The office (`bodies/office/`): a body's issuing service. The school pilot end
 * to end over its HTTP routes, checked at the kids' world gate with
 * `verifyPresentation`, and a scan that no name leaves the office.
 */
import { afterAll, beforeEach, describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PrivateKey } from '@bsv/sdk';
import {
  type BodyClaim,
  decodeStatusList,
  didKeyOfSecret,
  fromB64url,
  fromUtf8,
  present,
  readRegistryEntry,
  relationshipKey,
  signJwt,
  statusListBit,
  verifyPresentation,
} from '../src';
import {
  Office,
  PICKUP_MAX_SUBJECTS,
  PICKUP_TTL,
  fileStore,
  initState,
  officeHandler,
  pickupProof,
  serveOffice,
} from '../bodies/office';

const key = (label: string): PrivateKey =>
  PrivateKey.fromString(createHash('sha256').update(`gip-v2-office-test/${label}`).digest('hex'), 16);
const payloadOf = (jwt: string) => JSON.parse(fromUtf8(fromB64url(jwt.split('.')[1]!)));
const at = (iso: string): number => Date.parse(iso) / 1000;

const NOW = at('2026-11-05T09:00:00Z');
const END_2026 = '2026-12-31T23:59:59Z';
const END_2027 = '2027-12-31T23:59:59Z';
const DID = 'did:web:hillside.example.edu.au';
const BASE = 'https://hillside.example.edu.au';
const STATUS_URL = `${BASE}/status/1`;
const RP = 'kids-world:gem-island';

const anchor = key('hillside/anchor');
const steward = key('steward');
const STEWARDS = new Set([didKeyOfSecret(steward)]);

/** The school's own roster. None of it may leave the office. */
const ROSTER = [
  { id: 'HP-0042', kind: 'member', label: 'Mia Ellis', group: 'Room 3B' },
  { id: 'HP-0043', kind: 'member', label: 'Theo Ellis', group: 'Room 5A' },
  { id: 'HP-G-0042a', kind: 'guardian', label: 'Sam Ellis', guardianOf: ['HP-0042', 'HP-0043'] },
  { id: 'HP-G-0042b', kind: 'guardian', label: 'Jo Ellis-Okafor', guardianOf: ['HP-0042', 'HP-0043'] },
  { id: 'HP-0050', kind: 'member', label: 'Lena Brandt', group: 'Room 3B' },
];
const NAMES = [
  ...ROSTER.flatMap((r) => [r.id, r.label, r.group ?? r.label]),
  'Ellis',
  'Brandt',
  'Okafor',
  'Room',
];

const dir = mkdtempSync(join(tmpdir(), 'gip-office-test-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

let clock = NOW;
beforeEach(() => {
  clock = NOW;
});

type Handler = (req: Request) => Promise<Response>;
interface Reply {
  status: number;
  text: string;
  json: any;
  headers: Headers;
}

async function call(h: Handler, method: string, path: string, body?: unknown, auth?: string): Promise<Reply> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (auth !== undefined) headers.authorization = auth;
  const res = await h(
    new Request(`${BASE}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }),
  );
  const text = await res.text();
  let json: any = null;
  try {
    json = JSON.parse(text);
  } catch {}
  return { status: res.status, text, json, headers: res.headers };
}

/** Every public response this file sees, for the names scan. */
const publicSeen: string[] = [];

function makeOffice(name: string, claims: BodyClaim[] = ['member', 'guardian_of_member']) {
  const { state, token } = initState({
    did: DID,
    anchorSk: anchor,
    stewardSk: steward,
    kind: 'school',
    claims,
    periodEnds: [END_2026, END_2027],
    now: NOW - 86400,
  });
  const path = join(dir, `${name}.json`);
  const store = fileStore(path);
  store.save(state);
  const office = new Office(store, { now: () => clock });
  const h = officeHandler(office);
  const desk = (method: string, p: string, body?: unknown) => call(h, method, p, body, `Bearer ${token}`);
  const pub = async (method: string, p: string, body?: unknown) => {
    const r = await call(h, method, p, body);
    publicSeen.push(r.text);
    return r;
  };
  return { office, h, token, path, desk, pub };
}

const codeOf = (url: string): string => url.slice(url.lastIndexOf('/') + 1);

/** A holder's relationship key for one app, from their wallet root. */
const holder = (who: string, app = RP) => relationshipKey(key(`${who}/root`), app);

function gate(entryJwt: string, listJwt: string, require: BodyClaim, nonce: string) {
  return {
    audience: RP,
    nonce,
    stewards: STEWARDS,
    registryEntries: [entryJwt],
    statusLists: { [STATUS_URL]: listJwt },
    now: clock,
    require,
  };
}

function admit(credential: string, sk: PrivateKey, entryJwt: string, listJwt: string, require: BodyClaim) {
  const nonce = crypto.randomUUID();
  const vp = present({ credentialJwt: credential, subjectSk: sk, audience: RP, nonce, at: clock });
  return verifyPresentation(vp, gate(entryJwt, listJwt, require, nonce));
}

describe('the pilot, end to end', () => {
  const o = makeOffice('pilot');
  const codes: Record<string, string> = {};
  const creds: Record<string, string> = {};
  let entryJwt = '';
  let listJwt = '';

  async function redeem(code: string, sk: PrivateKey) {
    return o.pub('POST', `/pickup/${code}`, { proof: pickupProof({ subjectSk: sk, body: DID, code, at: clock }) });
  }

  test('the registrar adds a family and records consent', async () => {
    const r = await o.desk('POST', '/desk/roster', { rows: ROSTER });
    expect(r.status).toBe(200);
    expect(r.json.rows).toHaveLength(5);
    expect(r.json.rows[0]).toEqual({ id: 'HP-0042', kind: 'member', label: 'Mia Ellis', group: 'Room 3B', consent: false });

    const c = await o.desk('POST', '/desk/consent', { ids: ['HP-0042', 'HP-0043', 'HP-G-0042a', 'HP-G-0042b'], consent: true });
    expect(c.status).toBe(200);

    const needs = await o.desk('GET', '/desk/needs');
    expect(needs.status).toBe(200);
    expect(needs.json.periodEnd).toBe(END_2026);
    expect(needs.json.consentNotVouched.map((i: any) => i.id).sort()).toEqual(['HP-0042', 'HP-0043', 'HP-G-0042a', 'HP-G-0042b']);
    expect(needs.json.consentNotVouched.find((i: any) => i.id === 'HP-0042').label).toBe('Mia Ellis');
    expect(needs.json.counts).toEqual({
      members: 3,
      guardians: 2,
      consented: 4,
      vouched: 0,
      awaitingPickup: 0,
      withdrawn: 0,
      liveVouches: 0,
    });
  });

  test('vouching a class gives a pickup for each consented row and refuses the row without consent', async () => {
    const r = await o.desk('POST', '/desk/vouch', { ids: ['HP-0042', 'HP-0043', 'HP-G-0042a', 'HP-0050'] });
    expect(r.status).toBe(200);
    expect(r.json.refused).toEqual([{ id: 'HP-0050', reason: 'no_consent' }]);
    expect(r.json.pickups.map((p: any) => [p.id, p.claim])).toEqual([
      ['HP-0042', 'member'],
      ['HP-0043', 'member'],
      ['HP-G-0042a', 'guardian_of_member'],
    ]);
    for (const p of r.json.pickups) {
      expect(p.url).toMatch(/^https:\/\/hillside\.example\.edu\.au\/pickup\/[A-Za-z0-9_-]{22}$/);
      expect(p.expiresAt).toBe('2026-11-12T09:00:00Z');
      expect(p.validUntil).toBe(END_2026);
      codes[p.id] = codeOf(p.url);
    }
    expect(new Set(Object.values(codes)).size).toBe(3);
    const needs = await o.desk('GET', '/desk/needs');
    expect(needs.json.counts.awaitingPickup).toBe(3);
    expect(needs.json.consentNotVouched.map((i: any) => i.id)).toEqual(['HP-G-0042b']);
  });

  test('the parent scans the code and sees what the school will say, and no name', async () => {
    const r = await o.pub('GET', `/pickup/${codes['HP-0042']}`);
    expect(r.status).toBe(200);
    expect(r.headers.get('access-control-allow-origin')).toBe('*');
    expect(r.json).toMatchObject({
      body: DID,
      kind: 'school',
      claim: 'member',
      validUntil: END_2026,
      expiresAt: '2026-11-12T09:00:00Z',
      redemptionsLeft: PICKUP_MAX_SUBJECTS,
    });
    expect(r.json.willNotSay).toContain('name');
    expect(readRegistryEntry(r.json.registryEntry)).toMatchObject({ did: DID, kind: 'school', statusList: STATUS_URL });
    entryJwt = r.json.registryEntry;
    for (const s of NAMES) expect(r.text).not.toContain(s);
  });

  test('the child\'s key for Gem Island picks up the member vouch, and the gate lets the child in', async () => {
    const mia = holder('mia');
    const r = await redeem(codes['HP-0042']!, mia);
    expect(r.status).toBe(200);
    creds.mia = r.json.credential;
    const p = payloadOf(creds.mia!);
    expect(p.issuer).toBe(DID);
    expect(p.credentialSubject).toEqual({ id: didKeyOfSecret(mia), member: true });
    expect(p.validFrom).toBe('2026-11-05T00:00:00Z');
    expect(p.validUntil).toBe(END_2026);
    expect(p.credentialStatus.statusListCredential).toBe(STATUS_URL);

    const list = await o.pub('GET', '/status/1');
    expect(list.status).toBe(200);
    expect(list.headers.get('content-type')).toBe('application/vc+jwt');
    listJwt = list.text;
    expect(admit(creds.mia!, mia, entryJwt, listJwt, 'member')).toEqual({
      ok: true,
      body: { did: DID, kind: 'school' },
      claim: 'member',
      subject: didKeyOfSecret(mia),
    });
  });

  test('a guardian picks up guardian_of_member and the gate accepts it', async () => {
    const sam = holder('sam');
    const r = await redeem(codes['HP-G-0042a']!, sam);
    expect(r.status).toBe(200);
    creds.sam = r.json.credential;
    expect(payloadOf(creds.sam!).credentialSubject).toEqual({ id: didKeyOfSecret(sam), guardian_of_member: true });
    expect(admit(creds.sam!, sam, entryJwt, listJwt, 'guardian_of_member')).toMatchObject({ ok: true });
    expect(admit(creds.sam!, sam, entryJwt, listJwt, 'member')).toEqual({ ok: false, reason: 'missing_claim' });
  });

  test('the second guardian shows on the home list, and is vouched in turn', async () => {
    const before = await o.desk('GET', '/desk/needs');
    expect(before.json.secondGuardians).toEqual([
      { id: 'HP-G-0042b', kind: 'guardian', label: 'Jo Ellis-Okafor', consent: true, pickupOpen: false },
    ]);
    expect(before.json.consentNotVouched).toEqual([]);

    const v = await o.desk('POST', '/desk/vouch', { ids: ['HP-G-0042b'] });
    expect(v.json.pickups).toHaveLength(1);
    const jo = holder('jo');
    const r = await redeem(codeOf(v.json.pickups[0].url), jo);
    expect(r.status).toBe(200);
    creds.jo = r.json.credential;
    expect(admit(creds.jo!, jo, entryJwt, listJwt, 'guardian_of_member')).toMatchObject({ ok: true });

    const after = await o.desk('GET', '/desk/needs');
    expect(after.json.secondGuardians).toEqual([]);
  });

  test('a stale, wrong-audience, wrong-nonce or malformed proof is refused', async () => {
    const code = codes['HP-0043']!;
    const theo = holder('theo');
    const proof = (over: { body?: string; code?: string; at?: number } = {}) =>
      pickupProof({ subjectSk: theo, body: over.body ?? DID, code: over.code ?? code, at: over.at ?? clock });
    const tries: [unknown, number, string][] = [
      [proof({ at: clock - 301 }), 400, 'stale'],
      [proof({ at: clock + 301 }), 400, 'stale'],
      [proof({ body: 'did:web:other.example.org' }), 400, 'wrong_audience'],
      [proof({ code: codes['HP-0042'] }), 400, 'wrong_nonce'],
      ['not-a-jwt', 400, 'bad_proof'],
      [present({ credentialJwt: 'x', subjectSk: theo, audience: DID, nonce: code, at: clock }), 400, 'bad_proof'],
      [signJwt({ aud: DID, nonce: code, iat: clock }, theo), 400, 'bad_proof'],
      [undefined, 400, 'bad_proof'],
    ];
    for (const [p, status, error] of tries) {
      const r = await o.pub('POST', `/pickup/${code}`, p === undefined ? {} : { proof: p });
      expect([r.status, r.json.error]).toEqual([status, error]);
    }
    expect((await o.pub('GET', `/pickup/${code}`)).json.redemptionsLeft).toBe(PICKUP_MAX_SUBJECTS);

    const ok = await o.pub('POST', `/pickup/${code}`, { proof: proof({ at: clock - 300 }) });
    expect(ok.status).toBe(200);
    creds.theo = ok.json.credential;
    expect(admit(creds.theo!, theo, entryJwt, listJwt, 'member')).toMatchObject({ ok: true });
  });

  test('a key already holding one row\'s vouch cannot pick up another row\'s', async () => {
    const r = await redeem(codes['HP-0043']!, holder('mia'));
    expect([r.status, r.json.error]).toEqual([409, 'subject_taken']);
  });

  test('one pickup serves up to four subjects, one per app; a repeat is the same vouch; the fifth is 410', async () => {
    const code = codes['HP-0042']!;
    const apps = ['homework-club:online', 'library:reading-log', 'swim-club:app'];
    const indexes = new Set([payloadOf(creds.mia!).credentialStatus.statusListIndex]);
    for (const app of apps) {
      const r = await redeem(code, holder('mia', app));
      expect(r.status).toBe(200);
      indexes.add(payloadOf(r.json.credential).credentialStatus.statusListIndex);
    }
    expect(indexes.size).toBe(4);
    const again = await redeem(code, holder('mia'));
    expect(again.status).toBe(200);
    expect(again.json.credential).toBe(creds.mia);

    const fifth = await redeem(code, holder('mia', 'fifth-app:online'));
    expect([fifth.status, fifth.json.error]).toEqual([410, 'used_up']);
    expect((await o.pub('GET', `/pickup/${code}`)).status).toBe(410);
  });

  test('the home list shows this year\'s vouches lapsing at the period end', async () => {
    const needs = await o.desk('GET', '/desk/needs');
    expect(needs.json.lapsing.map((i: any) => [i.id, i.lapsesAt])).toEqual([
      ['HP-0042', END_2026],
      ['HP-0043', END_2026],
      ['HP-G-0042a', END_2026],
      ['HP-G-0042b', END_2026],
    ]);
    expect(needs.json.counts).toMatchObject({ vouched: 4, awaitingPickup: 0, liveVouches: 7 });
  });

  test('withdrawing a child re-signs the list: the gate says withdrawn, the sibling still passes', async () => {
    clock += 60;
    const r = await o.desk('POST', '/desk/withdraw', { ids: ['HP-0042'], sponsorNote: true });
    expect(r.status).toBe(200);
    expect(r.json.withdrawn).toHaveLength(1);
    const miaIndexes: number[] = r.json.withdrawn[0].statusIndexes;
    expect(miaIndexes).toHaveLength(4);
    // One child's vouches for four apps must not sit side by side on the list,
    // or two apps comparing indexes could tell they hold the same child.
    const sorted = [...miaIndexes].sort((a, b) => a - b);
    expect(sorted.some((x, i) => i > 0 && x - sorted[i - 1]! > 1)).toBe(true);
    expect(new Set(miaIndexes).size).toBe(4);

    const list = await o.pub('GET', '/status/1');
    expect(list.text).not.toBe(listJwt);
    const bits = decodeStatusList(payloadOf(list.text).credentialSubject.encodedList);
    for (const i of miaIndexes) expect(statusListBit(bits, i)).toBe(true);
    const theoIndex = Number(payloadOf(creds.theo!).credentialStatus.statusListIndex);
    expect(statusListBit(bits, theoIndex)).toBe(false);

    expect(admit(creds.mia!, holder('mia'), entryJwt, list.text, 'member')).toEqual({ ok: false, reason: 'withdrawn' });
    expect(admit(creds.theo!, holder('theo'), entryJwt, list.text, 'member')).toMatchObject({ ok: true });
    expect(admit(creds.sam!, holder('sam'), entryJwt, list.text, 'guardian_of_member')).toMatchObject({ ok: true });
    // The list the app held before the withdrawal still says yes: apps refetch it.
    expect(admit(creds.mia!, holder('mia'), entryJwt, listJwt, 'member')).toMatchObject({ ok: true });

    const rows = (await o.desk('GET', '/desk/roster')).json.rows;
    expect(rows.find((x: any) => x.id === 'HP-0042')).toMatchObject({ withdrawnAt: '2026-11-05T09:01:00Z', sponsorNote: true });
    const needs = await o.desk('GET', '/desk/needs');
    expect(needs.json.consentNotVouched).toEqual([]);
    expect(needs.json.counts).toMatchObject({ withdrawn: 1, vouched: 3 });
  });

  test('a family leaving: the child and the guardians whose children are all going', async () => {
    await o.desk('POST', '/desk/roster', { rows: [{ id: 'HP-0043', leavingOn: '2026-12-11' }] });
    const needs = await o.desk('GET', '/desk/needs');
    expect(needs.json.leaving.map((i: any) => [i.id, i.leavingOn])).toEqual([
      ['HP-0043', '2026-12-11'],
      ['HP-G-0042a', '2026-12-11'],
      ['HP-G-0042b', '2026-12-11'],
    ]);
    expect(needs.json.lapsing).toEqual([]);
  });

  test('withdrawing consent cancels a waiting pickup and flags a live vouch', async () => {
    await o.desk('POST', '/desk/consent', { ids: ['HP-0050'], consent: true });
    const v = await o.desk('POST', '/desk/vouch', { ids: ['HP-0050'] });
    const code = codeOf(v.json.pickups[0].url);
    const c = await o.desk('POST', '/desk/consent', { ids: ['HP-0050', 'HP-G-0042b'], consent: false });
    // Lena's slip, and Jo's, which had redemptions left.
    expect(c.json).toEqual({ updated: ['HP-0050', 'HP-G-0042b'], cancelledPickups: 2 });
    const r = await o.pub('GET', `/pickup/${code}`);
    expect([r.status, r.json.error]).toEqual([410, 'cancelled']);
    const needs = await o.desk('GET', '/desk/needs');
    expect(needs.json.consentWithdrawn.map((i: any) => i.id)).toEqual(['HP-G-0042b']);
  });

  test('the DID document lists the anchor as a secp256k1 key', async () => {
    const r = await o.pub('GET', '/.well-known/did.json');
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type')).toBe('application/did+json');
    const vm = `${DID}#anchor`;
    expect(r.json).toEqual({
      '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
      id: DID,
      verificationMethod: [
        {
          id: vm,
          type: 'Multikey',
          controller: DID,
          publicKeyMultibase: didKeyOfSecret(anchor).slice('did:key:'.length),
        },
      ],
      assertionMethod: [vm],
      capabilityDelegation: [vm],
    });
    expect(r.json.verificationMethod[0].publicKeyMultibase).toStartWith('zQ3s');
  });

  test('names never leave: no public response or JWT payload carries a label, group or roster id', () => {
    expect(publicSeen.length).toBeGreaterThan(20);
    const texts: string[] = [];
    for (const body of publicSeen) {
      texts.push(body);
      for (const jwt of body.match(/eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+/g) ?? []) {
        const p = payloadOf(jwt);
        texts.push(JSON.stringify(p));
        if (typeof p.vp === 'string') texts.push(JSON.stringify(payloadOf(p.vp)));
      }
    }
    for (const t of texts) for (const s of NAMES) expect(t).not.toContain(s);
    // Credentials were among them.
    expect(texts.some((t) => t.includes('"member":true'))).toBe(true);
    expect(texts.some((t) => t.includes('"guardian_of_member":true'))).toBe(true);
  });
});

describe('pickups', () => {
  const o = makeOffice('pickups');

  async function fresh(id: string): Promise<string> {
    await o.desk('POST', '/desk/roster', { rows: [{ id, kind: 'member', label: `Child ${id}` }] });
    await o.desk('POST', '/desk/consent', { ids: [id], consent: true });
    const v = await o.desk('POST', '/desk/vouch', { ids: [id] });
    return codeOf(v.json.pickups[0].url);
  }

  test('one person\'s vouches get scattered list indexes, so apps cannot match them by place', async () => {
    clock = NOW;
    const code = await fresh('p-idx');
    const indexes: number[] = [];
    for (const app of ['a', 'b', 'c', 'd']) {
      const r = await o.pub('POST', `/pickup/${code}`, { proof: pickupProof({ subjectSk: holder(`p-idx-${app}`), body: DID, code, at: clock }) });
      expect(r.status).toBe(200);
      indexes.push(Number(payloadOf(r.json.credential).credentialStatus.statusListIndex));
    }
    expect(new Set(indexes).size).toBe(4);
    const sorted = [...indexes].sort((a, b) => a - b);
    // Handed out in order, four redemptions in a row would be a run of four.
    expect(sorted.every((x, i) => i === 0 || x === sorted[i - 1]! + 1)).toBe(false);
  });

  test('an expired pickup is 410, for a look and for a redemption', async () => {
    const code = await fresh('p-1');
    clock = NOW + PICKUP_TTL - 1;
    expect((await o.pub('GET', `/pickup/${code}`)).status).toBe(200);
    clock = NOW + PICKUP_TTL;
    const g = await o.pub('GET', `/pickup/${code}`);
    expect([g.status, g.json.error]).toEqual([410, 'expired']);
    const sk = holder('p-1');
    const r = await o.pub('POST', `/pickup/${code}`, { proof: pickupProof({ subjectSk: sk, body: DID, code, at: clock }) });
    expect([r.status, r.json.error]).toEqual([410, 'expired']);
  });

  test('vouching again replaces a waiting pickup; the old code is 410', async () => {
    const first = await fresh('p-2');
    const v = await o.desk('POST', '/desk/vouch', { ids: ['p-2'] });
    const second = codeOf(v.json.pickups[0].url);
    expect((await o.pub('GET', `/pickup/${first}`)).status).toBe(410);
    expect((await o.pub('GET', `/pickup/${second}`)).status).toBe(200);
  });

  test('a pickup never outlives the period it vouches for, and the next period can be chosen', async () => {
    clock = at(END_2026) - 3600;
    await fresh('p-3');
    const v = await o.desk('POST', '/desk/vouch', { ids: ['p-3'] });
    expect(v.json.pickups[0]).toMatchObject({ expiresAt: END_2026, validUntil: END_2026 });
    const next = await o.desk('POST', '/desk/vouch', { ids: ['p-3'], periodEnd: END_2027 });
    expect(next.json.pickups[0]).toMatchObject({ expiresAt: '2027-01-07T22:59:59Z', validUntil: END_2027 });
    const bad = await o.desk('POST', '/desk/vouch', { ids: ['p-3'], periodEnd: '2027-03-04T00:00:00Z' });
    expect([bad.status, bad.json.error]).toEqual([400, 'not_a_period_end']);
  });

  test('an unknown or malformed code is 404', async () => {
    expect((await o.pub('GET', '/pickup/AAAAAAAAAAAAAAAAAAAAAA')).status).toBe(404);
    expect((await o.pub('GET', '/pickup/short')).status).toBe(404);
    expect((await o.pub('GET', '/status/2')).status).toBe(404);
  });

  test('a claim the registry entry does not list is refused', async () => {
    const m = makeOffice('members-only', ['member']);
    await m.desk('POST', '/desk/roster', {
      rows: [
        { id: 'c-1', kind: 'member', label: 'Child One' },
        { id: 'g-1', kind: 'guardian', label: 'Parent One', guardianOf: ['c-1'] },
      ],
    });
    await m.desk('POST', '/desk/consent', { ids: ['c-1', 'g-1'], consent: true });
    const v = await m.desk('POST', '/desk/vouch', { ids: ['c-1', 'g-1'] });
    expect(v.json.pickups.map((p: any) => p.id)).toEqual(['c-1']);
    expect(v.json.refused).toEqual([{ id: 'g-1', reason: 'claim_not_allowed' }]);
  });

  test('a row that has left, a guardian of no member, and an unknown id are refused', async () => {
    await o.desk('POST', '/desk/roster', {
      rows: [
        { id: 'gone', kind: 'member', label: 'Gone Child', leavingOn: '2026-11-05' },
        { id: 'lone', kind: 'guardian', label: 'Lone Adult', guardianOf: [] },
      ],
    });
    await o.desk('POST', '/desk/consent', { ids: ['gone', 'lone'], consent: true });
    const v = await o.desk('POST', '/desk/vouch', { ids: ['gone', 'lone', 'nobody'] });
    expect(v.json).toEqual({
      pickups: [],
      refused: [
        { id: 'gone', reason: 'left' },
        { id: 'lone', reason: 'no_member' },
        { id: 'nobody', reason: 'unknown_row' },
      ],
    });
  });
});

describe('the roster', () => {
  const o = makeOffice('roster');

  test('a bad row changes nothing', async () => {
    const tries: [unknown, string][] = [
      [{ rows: [{ id: 'a', kind: 'member' }] }, 'bad_row'],
      [{ rows: [{ id: 'a', kind: 'pupil', label: 'A' }] }, 'bad_row'],
      [{ rows: [{ id: 'a', kind: 'member', label: 'A', consent: true }] }, 'bad_row'],
      [{ rows: [{ id: 'a', kind: 'member', label: 'A', leavingOn: '2026-02-30' }] }, 'bad_row'],
      [{ rows: [{ id: 'g', kind: 'guardian', label: 'G', guardianOf: ['nobody'] }] }, 'bad_row'],
      [{ rows: [{ id: 'has space', kind: 'member', label: 'A' }] }, 'bad_row'],
      [{ rows: 'nope' }, 'bad_request'],
    ];
    for (const [body, error] of tries) {
      const r = await o.desk('POST', '/desk/roster', body);
      expect([r.status, r.json.error]).toEqual([400, error]);
    }
    expect((await o.desk('GET', '/desk/roster')).json.rows).toEqual([]);
  });

  test('rows are added and updated in one batch; a kind is fixed once set', async () => {
    const r = await o.desk('POST', '/desk/roster', {
      rows: [
        { kind: 'member', label: 'New Child' },
        { id: 'g', kind: 'guardian', label: 'G', guardianOf: ['c'] },
        { id: 'c', kind: 'member', label: 'C', group: 'Room 1' },
      ],
    });
    expect(r.status).toBe(200);
    expect(r.json.rows[0].id).toMatch(/^[A-Za-z0-9_-]{12}$/);
    const u = await o.desk('POST', '/desk/roster', { rows: [{ id: 'c', group: null, label: 'C two' }] });
    expect(u.json.rows).toEqual([{ id: 'c', kind: 'member', label: 'C two', consent: false }]);
    const k = await o.desk('POST', '/desk/roster', { rows: [{ id: 'c', kind: 'guardian' }] });
    expect([k.status, k.json.error]).toEqual([400, 'bad_row']);
    const unknown = await o.desk('POST', '/desk/consent', { ids: ['c', 'zz'], consent: true });
    expect([unknown.status, unknown.json.error]).toEqual([400, 'unknown_rows']);
    expect((await o.desk('GET', '/desk/roster')).json.rows.find((x: any) => x.id === 'c').consent).toBe(false);
  });
});

describe('the registrar token', () => {
  const o = makeOffice('token');
  const routes: [string, string, unknown?][] = [
    ['GET', '/desk/roster'],
    ['POST', '/desk/roster', { rows: [] }],
    ['POST', '/desk/consent', { ids: [], consent: true }],
    ['POST', '/desk/vouch', { ids: [] }],
    ['POST', '/desk/withdraw', { ids: [] }],
    ['GET', '/desk/needs'],
  ];

  test('every registrar route refuses a missing or wrong token, and takes the right one', async () => {
    for (const [method, path, body] of routes) {
      const none = await call(o.h, method, path, body);
      expect([none.status, none.json.error]).toEqual([401, 'no_token']);
      expect(none.headers.get('www-authenticate')).toStartWith('Bearer');
      for (const auth of ['Bearer wrong', `Basic ${o.token}`, `Bearer ${o.token}x`, 'Bearer ']) {
        const bad = await call(o.h, method, path, body, auth);
        expect(bad.status).toBe(401);
      }
      expect((await o.desk(method, path, body)).status).toBe(200);
    }
  });

  test('the token is stored hashed; rotating it retires the old one', async () => {
    const text = readFileSync(o.path, 'utf8');
    expect(text).not.toContain(o.token);
    expect(JSON.parse(text).tokenHash).toBe(createHash('sha256').update(o.token).digest('hex'));
    const next = o.office.rotateToken();
    expect((await call(o.h, 'GET', '/desk/needs', undefined, `Bearer ${o.token}`)).status).toBe(401);
    expect((await call(o.h, 'GET', '/desk/needs', undefined, `Bearer ${next}`)).status).toBe(200);
  });
});

describe('the state file', () => {
  test('is written atomically with mode 0600, and holds the keys and roster', async () => {
    const o = makeOffice('state');
    await o.desk('POST', '/desk/roster', { rows: [{ id: 'x', kind: 'member', label: 'X' }] });
    expect(statSync(o.path).mode & 0o777).toBe(0o600);
    expect(readdirSync(dir).filter((f) => f.endsWith('.tmp'))).toEqual([]);
    const s = JSON.parse(readFileSync(o.path, 'utf8'));
    expect(s).toMatchObject({ version: 1, did: DID, baseUrl: BASE, anchor: anchor.toPublicKey().toString(), nextStatusIndex: 0 });
    expect(s.nodeKey).toMatch(/^[0-9a-f]{64}$/);
    expect(readRegistryEntry(s.registryEntry)?.steward).toBe(didKeyOfSecret(steward));
    expect(s.roster).toEqual([{ id: 'x', kind: 'member', label: 'X', consent: false }]);
  });

  test('a steward that is the body\'s own anchor is refused', () => {
    expect(() =>
      initState({ did: DID, anchorSk: anchor, stewardSk: anchor, kind: 'school', claims: ['member'], periodEnds: [END_2026], now: NOW }),
    ).toThrow('self_registration');
  });

  test('an entry from a steward elsewhere is taken if it names this body and anchor', () => {
    const { state } = initState({ did: DID, anchorSk: anchor, stewardSk: steward, kind: 'club', claims: ['member'], periodEnds: [END_2026], now: NOW });
    expect(initState({ did: DID, anchorSk: anchor, entry: state.registryEntry, now: NOW }).state.registryEntry).toBe(state.registryEntry);
    expect(() => initState({ did: DID, anchorSk: key('other-anchor'), entry: state.registryEntry, now: NOW })).toThrow('anchor');
    expect(() => initState({ did: 'did:web:other.example.org', anchorSk: anchor, entry: state.registryEntry, now: NOW })).toThrow('did');
  });
});

describe('the server', () => {
  test('answers over HTTP', async () => {
    const o = makeOffice('server');
    const server = serveOffice(o.office, { port: 0, hostname: '127.0.0.1' });
    try {
      const base = `http://127.0.0.1:${server.port}`;
      const did = await fetch(`${base}/.well-known/did.json`);
      expect(did.status).toBe(200);
      expect((await did.json()).id).toBe(DID);
      const needs = await fetch(`${base}/desk/needs`, { headers: { authorization: `Bearer ${o.token}` } });
      expect(needs.status).toBe(200);
      const pre = await fetch(`${base}/pickup/AAAAAAAAAAAAAAAAAAAAAA`, { method: 'OPTIONS' });
      expect(pre.status).toBe(204);
      expect(pre.headers.get('access-control-allow-methods')).toContain('POST');
      expect((await fetch(`${base}/nowhere`)).status).toBe(404);
      expect((await fetch(`${base}/desk/needs`, { method: 'DELETE' })).status).toBe(405);
    } finally {
      server.stop(true);
    }
  });
});

describe('the CLI', () => {
  const cli = (...args: string[]) => {
    const r = Bun.spawnSync([process.execPath, 'bodies/office/cli.ts', ...args], { cwd: join(import.meta.dir, '..') });
    return { code: r.exitCode, out: r.stdout.toString(), err: r.stderr.toString() };
  };
  const year = new Date().getUTCFullYear() + 1;
  const ends = `${year}-12-31T23:59:59Z,${year + 1}-12-31T23:59:59Z`;

  test('keygen, init with a local steward (and a loud warning), token rotation', () => {
    const anchorFile = join(dir, 'cli-anchor.key');
    const stewardFile = join(dir, 'cli-steward.key');
    const state = join(dir, 'cli-office.json');
    expect(cli('keygen', anchorFile).code).toBe(0);
    expect(cli('keygen', stewardFile).code).toBe(0);
    expect(statSync(anchorFile).mode & 0o777).toBe(0o600);
    expect(cli('keygen', anchorFile).code).not.toBe(0);

    const init = ['init', '--state', state, '--did', DID, '--anchor-key', anchorFile, '--kind', 'school', '--period-ends', ends];
    const selfRun = cli(...init, '--steward-key', anchorFile);
    expect(selfRun.code).not.toBe(0);
    expect(existsSync(state)).toBe(false);

    const run = cli(...init, '--steward-key', stewardFile);
    expect(run.code).toBe(0);
    expect(run.err).toContain('A BODY MUST NOT STEWARD ITSELF');
    expect(statSync(state).mode & 0o777).toBe(0o600);
    const token = run.out.match(/registrar token[^\n]*\n\s+(\S+)/)?.[1];
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const s = JSON.parse(readFileSync(state, 'utf8'));
    expect(s.anchor).toBe(PrivateKey.fromString(readFileSync(anchorFile, 'utf8').trim(), 16).toPublicKey().toString());
    expect(JSON.stringify(s)).not.toContain(readFileSync(anchorFile, 'utf8').trim());
    expect(cli(...init, '--steward-key', stewardFile).code).not.toBe(0);

    const office = new Office(fileStore(state));
    expect(office.checkToken(token!)).toBe(true);
    const rot = cli('token', '--state', state);
    expect(rot.code).toBe(0);
    const next = rot.out.trim().split('\n').at(-1)!.trim();
    expect(next).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(office.checkToken(token!)).toBe(false);
    expect(office.checkToken(next)).toBe(true);
  });

  test('init takes a steward-signed entry from a file', () => {
    const anchorFile = join(dir, 'cli2-anchor.key');
    writeFileSync(anchorFile, anchor.toHex(), { mode: 0o600 });
    const { state: made } = initState({
      did: DID,
      anchorSk: anchor,
      stewardSk: steward,
      kind: 'school',
      claims: ['member', 'guardian_of_member'],
      periodEnds: ends.split(','),
      now: Math.floor(Date.now() / 1000),
    });
    const entryFile = join(dir, 'cli2-entry.jwt');
    writeFileSync(entryFile, made.registryEntry);
    const state = join(dir, 'cli2-office.json');
    const run = cli('init', '--state', state, '--did', DID, '--anchor-key', anchorFile, '--entry', entryFile);
    expect(run.code).toBe(0);
    expect(run.err).not.toContain('MUST NOT STEWARD');
    expect(JSON.parse(readFileSync(state, 'utf8')).registryEntry).toBe(made.registryEntry);
  });
});
