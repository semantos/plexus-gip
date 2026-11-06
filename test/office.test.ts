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
  didKeyOf,
  didKeyOfSecret,
  didWebDocumentUrl,
  fromB64url,
  fromUtf8,
  present,
  readDelegation,
  readRegistryEntry,
  relationshipKey,
  signJwt,
  statusListBit,
  verifyJwtByKid,
  verifyPresentation,
  vouchOfficeOf,
} from '../src';
import {
  COLLECT_NONCE,
  Office,
  type OfficeHandlerOptions,
  PICKUP_MAX_SUBJECTS,
  PICKUP_TTL,
  collectProof,
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

async function call(h: Handler, method: string, path: string, body?: unknown, auth?: string, extra: Record<string, string> = {}): Promise<Reply> {
  const headers: Record<string, string> = { ...extra };
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

function makeOffice(name: string, claims: BodyClaim[] = ['member', 'guardian_of_member'], handler: OfficeHandlerOptions = {}) {
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
  const h = officeHandler(office, handler);
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
      vouchedMembers: 0,
      vouchedGuardians: 0,
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
    expect(needs.json.counts).toMatchObject({ vouched: 4, vouchedMembers: 2, vouchedGuardians: 2, awaitingPickup: 0, liveVouches: 7 });
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

  test('a new node: the anchor delegates it, it signs the list, which carries both delegations', async () => {
    const old = o.office.info();
    expect(old.nodes).toEqual([old.node]);
    const r = o.office.rotateNode(anchor);
    expect(r.node).not.toBe(old.node);
    expect(r.nodes).toEqual([r.node, old.node]);
    expect(o.office.info()).toMatchObject({ node: r.node, nodes: [r.node, old.node] });

    const list = await o.pub('GET', '/status/1');
    expect(list.text).not.toBe(listJwt);
    expect(verifyJwtByKid(list.text)?.signer).toBe(didKeyOf(r.node));
    expect(payloadOf(list.text).evidence.map((e: any) => readDelegation(e.delegation))).toEqual(
      [r.node, old.node].map((node) => ({ anchor: anchor.toPublicKey().toString(), node, purpose: 'body.vouch' })),
    );
    // The withdrawals carry over, and the old node's vouches still pass.
    expect(admit(creds.mia!, holder('mia'), entryJwt, list.text, 'member')).toEqual({ ok: false, reason: 'withdrawn' });
    expect(admit(creds.theo!, holder('theo'), entryJwt, list.text, 'member')).toMatchObject({ ok: true });
    expect(admit(creds.sam!, holder('sam'), entryJwt, list.text, 'guardian_of_member')).toMatchObject({ ok: true });

    // A vouch collected now is the new node's.
    const v = await o.desk('POST', '/desk/vouch', { ids: ['HP-0043'] });
    const got = await redeem(codeOf(v.json.pickups[0].url), holder('theo'));
    expect(got.status).toBe(200);
    creds.theoNew = got.json.credential;
    expect(verifyJwtByKid(creds.theoNew!)?.signer).toBe(didKeyOf(r.node));
    expect(admit(creds.theoNew!, holder('theo'), entryJwt, list.text, 'member')).toMatchObject({ ok: true });
    listJwt = list.text;
  });

  test('retiring the old node: the list drops its delegation, its vouches fail, the new node\'s pass', async () => {
    const [current, old] = o.office.info().nodes;
    const r = o.office.retireNode(old!);
    expect(r).toEqual({ retired: old, nodes: [current] });
    const list = await o.pub('GET', '/status/1');
    expect(list.text).not.toBe(listJwt);
    expect(payloadOf(list.text).evidence.map((e: any) => readDelegation(e.delegation)?.node)).toEqual([current]);
    expect(admit(creds.theo!, holder('theo'), entryJwt, list.text, 'member')).toEqual({ ok: false, reason: 'node_not_delegated' });
    expect(admit(creds.sam!, holder('sam'), entryJwt, list.text, 'guardian_of_member')).toEqual({ ok: false, reason: 'node_not_delegated' });
    expect(admit(creds.theoNew!, holder('theo'), entryJwt, list.text, 'member')).toMatchObject({ ok: true });
    // Until the app downloads the list again, the old one still honours the node.
    expect(admit(creds.theo!, holder('theo'), entryJwt, listJwt, 'member')).toMatchObject({ ok: true });
  });

  test('the DID document lists the anchor as a secp256k1 key, and names the office', async () => {
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
      service: [{ id: `${DID}#vouch-office`, type: 'BodyVouchOffice', serviceEndpoint: BASE }],
    });
    expect(r.json.verificationMethod[0].publicKeyMultibase).toStartWith('zQ3s');
    // A reader finds the document from the did, and the office from the document.
    expect(didWebDocumentUrl(DID)).toBe(`${BASE}/.well-known/did.json`);
    expect(vouchOfficeOf(r.json, DID)).toBe(BASE);
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

describe('collecting', () => {
  const o = makeOffice('collect');
  const HOMEWORK = 'homework-club:online';
  const LIBRARY = 'library:reading-log';
  const codes: Record<string, string> = {};
  const creds: Record<string, string> = {};
  /** Every answer this block sees, for the names scan. */
  const seen: string[] = [];
  let entryJwt = '';

  async function collect(sk: PrivateKey, proof: unknown = collectProof({ subjectSk: sk, body: DID, at: clock })) {
    const r = await o.pub('POST', '/collect', { proof });
    seen.push(r.text);
    return r;
  }
  async function redeem(code: string, sk: PrivateKey) {
    const r = await o.pub('POST', `/pickup/${code}`, { proof: pickupProof({ subjectSk: sk, body: DID, code, at: clock }) });
    seen.push(r.text);
    return r;
  }
  const list = async (): Promise<string> => (await o.pub('GET', '/status/1')).text;
  const indexOf = (jwt: string): string => payloadOf(jwt).credentialStatus.statusListIndex;

  test('the family picks up at the office, as before', async () => {
    await o.desk('POST', '/desk/roster', { rows: ROSTER });
    await o.desk('POST', '/desk/consent', { ids: ['HP-0042', 'HP-0043', 'HP-G-0042a'], consent: true });
    const v = await o.desk('POST', '/desk/vouch', { ids: ['HP-0042', 'HP-0043', 'HP-G-0042a'] });
    for (const p of v.json.pickups) codes[p.id] = codeOf(p.url);
    entryJwt = (await o.pub('GET', `/pickup/${codes['HP-0042']}`)).json.registryEntry;
    const got: [string, string, PrivateKey][] = [
      ['mia', 'HP-0042', holder('mia')],
      ['miaHomework', 'HP-0042', holder('mia', HOMEWORK)],
      ['miaLibrary', 'HP-0042', holder('mia', LIBRARY)],
      ['theo', 'HP-0043', holder('theo')],
      ['sam', 'HP-G-0042a', holder('sam')],
    ];
    for (const [name, id, sk] of got) {
      const r = await redeem(codes[id]!, sk);
      expect(r.status).toBe(200);
      creds[name] = r.json.credential;
    }
  });

  test('a key collects its own live vouches and nothing else, and a collect writes nothing', async () => {
    // A save renames a new file into place, so the inode says whether there was one.
    const before = statSync(o.path).ino;
    const r = await collect(holder('mia'));
    expect(r.status).toBe(200);
    expect(r.headers.get('access-control-allow-origin')).toBe('*');
    expect(r.json).toEqual({ vouches: [creds.mia] });
    expect((await collect(holder('mia', HOMEWORK))).json).toEqual({ vouches: [creds.miaHomework] });
    expect((await collect(holder('theo'))).json).toEqual({ vouches: [creds.theo] });
    expect((await collect(holder('sam'))).json).toEqual({ vouches: [creds.sam] });
    expect(admit(r.json.vouches[0], holder('mia'), entryJwt, await list(), 'member')).toMatchObject({ ok: true });
    expect(statSync(o.path).ino).toBe(before);
  });

  test('an unknown key, and one whose vouches are all withdrawn or ended, get the same empty list', async () => {
    const stranger = await collect(holder('stranger'));
    expect(stranger.status).toBe(200);
    expect(stranger.json).toEqual({ vouches: [] });

    clock += 60;
    await o.desk('POST', '/desk/withdraw', { ids: ['HP-0043'] });
    const theo = await collect(holder('theo'));
    expect([theo.status, theo.text]).toEqual([200, stranger.text]);

    clock = at(END_2026) - 1;
    expect((await collect(holder('mia'))).json.vouches).toEqual([creds.mia]);
    clock = at(END_2026);
    const mia = await collect(holder('mia'));
    expect([mia.status, mia.text]).toEqual([200, stranger.text]);
  });

  test('a stale, wrong-audience, wrong-nonce or malformed proof is refused', async () => {
    const mia = holder('mia');
    const proof = (over: { body?: string; nonce?: string; at?: number } = {}) =>
      signJwt({ aud: over.body ?? DID, nonce: over.nonce ?? COLLECT_NONCE, iat: over.at ?? clock }, mia, 'openid4vci-proof+jwt');
    expect(COLLECT_NONCE).toBe('collect');
    expect(collectProof({ subjectSk: mia, body: DID, at: clock })).toBe(proof());
    const tries: [unknown, string][] = [
      [proof({ at: clock - 301 }), 'stale'],
      [proof({ at: clock + 301 }), 'stale'],
      [proof({ body: 'did:web:other.example.org' }), 'wrong_audience'],
      [proof({ nonce: 'Collect' }), 'wrong_nonce'],
      [proof({ nonce: 'collect ' }), 'wrong_nonce'],
      [pickupProof({ subjectSk: mia, body: DID, code: codes['HP-0042']!, at: clock }), 'wrong_nonce'],
      ['not-a-jwt', 'bad_proof'],
      [present({ credentialJwt: 'x', subjectSk: mia, audience: DID, nonce: COLLECT_NONCE, at: clock }), 'bad_proof'],
      [signJwt({ aud: DID, nonce: COLLECT_NONCE, iat: clock }, mia), 'bad_proof'],
      [proof({ at: clock + 0.5 }), 'bad_proof'],
      [undefined, 'bad_proof'],
    ];
    for (const [p, error] of tries) {
      const r = await o.pub('POST', '/collect', p === undefined ? {} : { proof: p });
      seen.push(r.text);
      expect([r.status, r.json.error]).toEqual([400, error]);
    }
    expect((await collect(mia, proof({ at: clock - 300 }))).json.vouches).toEqual([creds.mia]);
    // Nor does a collect proof pick up a code.
    const code = codes['HP-0042']!;
    const asPickup = await o.pub('POST', `/pickup/${code}`, { proof: proof() });
    expect([asPickup.status, asPickup.json.error]).toEqual([400, 'wrong_nonce']);

    const notJson = await o.h(new Request(`${BASE}/collect`, { method: 'POST', body: 'nope' }));
    expect([notJson.status, (await notJson.json()).error]).toEqual([400, 'bad_json']);
    const get = await o.pub('GET', '/collect');
    expect([get.status, get.headers.get('allow')]).toEqual([405, 'POST']);
    const pre = await call(o.h, 'OPTIONS', '/collect');
    expect(pre.status).toBe(204);
    expect(pre.headers.get('access-control-allow-origin')).toBe('*');
    expect(pre.headers.get('access-control-allow-methods')).toBe('POST');
  });

  test('after a new node, a key collects the same vouch signed by the new node, and it passes the gate', async () => {
    const { node } = o.office.rotateNode(anchor);
    const r = await collect(holder('mia'));
    expect(r.json.vouches).toHaveLength(1);
    const v: string = r.json.vouches[0];
    expect(v).not.toBe(creds.mia);
    expect(verifyJwtByKid(v)?.signer).toBe(didKeyOf(node));
    // Same subject, claim, place and dates: only the signature is new.
    expect(payloadOf(v)).toEqual(payloadOf(creds.mia!));
    expect(admit(v, holder('mia'), entryJwt, await list(), 'member')).toMatchObject({ ok: true });

    // Once the old node is retired, the vouch held from before fails and the one collected passes.
    o.office.retireNode(o.office.info().nodes[1]!);
    const after = await list();
    expect(admit(creds.mia!, holder('mia'), entryJwt, after, 'member')).toEqual({ ok: false, reason: 'node_not_delegated' });
    expect(admit(v, holder('mia'), entryJwt, after, 'member')).toMatchObject({ ok: true });
    for (const [name, sk] of [['mia', holder('mia')], ['miaHomework', holder('mia', HOMEWORK)], ['sam', holder('sam')]] as const) {
      creds[name] = (await collect(sk)).json.vouches[0];
    }
  });

  test('renewal: vouched again for 2027, each key holding the row\'s vouch collects 2027\'s with no code', async () => {
    clock = NOW + 3 * 86400; // 2026-11-08T09:00:00Z
    const v = await o.desk('POST', '/desk/vouch', { ids: ['HP-0042'], periodEnd: END_2027 });
    const code = codeOf(v.json.pickups[0].url);
    // A week and a day later the code has run out, and nobody has used it.
    clock = NOW + 11 * 86400 + 3600; // 2026-11-16T10:00:00Z
    expect((await o.pub('GET', `/pickup/${code}`)).json.error).toBe('expired');
    // The home list knows the row is vouched for 2027: it is not lapsing; Sam's is.
    const needs = await o.desk('GET', '/desk/needs');
    expect(needs.json.lapsing.map((i: any) => i.id)).toEqual(['HP-G-0042a']);

    const r = await collect(holder('mia'));
    expect(r.json.vouches).toHaveLength(2);
    const [next, current] = r.json.vouches as string[];
    // This year's is still live: vouching for a later period cancels no vouch. Newest period first.
    expect(current).toBe(creds.mia);
    const p = payloadOf(next!);
    expect(p).toMatchObject({ issuer: DID, validFrom: '2026-11-08T00:00:00Z', validUntil: END_2027 });
    expect(p.credentialSubject).toEqual({ id: didKeyOfSecret(holder('mia')), member: true });
    expect(verifyJwtByKid(next!)?.signer).toBe(didKeyOf(o.office.info().node));
    const listJwt = await list();
    expect(admit(next!, holder('mia'), entryJwt, listJwt, 'member')).toMatchObject({ ok: true });
    expect(admit(current!, holder('mia'), entryJwt, listJwt, 'member')).toMatchObject({ ok: true });

    // Issued at collect time, at a new place of its own.
    const s = JSON.parse(readFileSync(o.path, 'utf8'));
    const renewed = s.vouches.filter((x: any) => x.validUntil === END_2027);
    expect(renewed).toEqual([
      {
        statusIndex: Number(indexOf(next!)),
        rosterId: 'HP-0042',
        claim: 'member',
        subject: didKeyOfSecret(holder('mia')),
        validFrom: '2026-11-08T00:00:00Z',
        issuedAt: '2026-11-16T10:00:00Z',
        validUntil: END_2027,
      },
    ]);
    expect(s.vouches.filter((x: any) => x.statusIndex === renewed[0].statusIndex)).toHaveLength(1);

    // Again: the same two, and no new place.
    clock += 60;
    expect((await collect(holder('mia'))).json.vouches).toEqual([next, current]);
    expect(JSON.parse(readFileSync(o.path, 'utf8')).vouches).toHaveLength(s.vouches.length);

    // The row's other keys get their own, each at its own place; another row's key gets nothing new.
    const hw = await collect(holder('mia', HOMEWORK));
    expect(hw.json.vouches).toHaveLength(2);
    expect(hw.json.vouches[1]).toBe(creds.miaHomework);
    expect(payloadOf(hw.json.vouches[0])).toMatchObject({ validUntil: END_2027, credentialSubject: { id: didKeyOfSecret(holder('mia', HOMEWORK)) } });
    expect(indexOf(hw.json.vouches[0])).not.toBe(indexOf(next!));
    expect((await collect(holder('sam'))).json.vouches).toEqual([creds.sam]);
    creds.mia2027 = next!;
    creds.miaHomework2027 = hw.json.vouches[0];
  });

  test('a lapsed vouch renews too: in 2027 a key that held only 2026\'s collects 2027\'s', async () => {
    clock = at(END_2026) + 86400;
    expect((await collect(holder('mia'))).json.vouches).toEqual([creds.mia2027]);
    const lib = await collect(holder('mia', LIBRARY));
    expect(lib.json.vouches).toHaveLength(1);
    expect(payloadOf(lib.json.vouches[0])).toMatchObject({ validUntil: END_2027, credentialSubject: { id: didKeyOfSecret(holder('mia', LIBRARY)) } });
    expect((await collect(holder('sam'))).json).toEqual({ vouches: [] });
  });

  test('without consent there is nothing new, and a withdrawn key is not renewed when its row is taken back', async () => {
    clock = NOW + 12 * 86400;
    await o.desk('POST', '/desk/vouch', { ids: ['HP-G-0042a'], periodEnd: END_2027 });
    await o.desk('POST', '/desk/consent', { ids: ['HP-G-0042a'], consent: false });
    expect((await collect(holder('sam'))).json.vouches).toEqual([creds.sam]);

    // Theo was withdrawn. Taking his row back for 2027 renews nobody: his key needs the code.
    const back = await o.desk('POST', '/desk/vouch', { ids: ['HP-0043'], periodEnd: END_2027 });
    expect(back.json.pickups).toHaveLength(1);
    expect((await collect(holder('theo'))).json).toEqual({ vouches: [] });
    const r = await redeem(codeOf(back.json.pickups[0].url), holder('theo'));
    expect(r.status).toBe(200);
    expect((await collect(holder('theo'))).json).toEqual({ vouches: [r.json.credential] });
  });

  test('withdrawal stops both periods; taken back for 2026, the withdrawn 2027 vouch does not come back', async () => {
    clock = NOW + 13 * 86400;
    await o.desk('POST', '/desk/withdraw', { ids: ['HP-0042'] });
    expect((await collect(holder('mia'))).json).toEqual({ vouches: [] });
    const listJwt = await list();
    for (const jwt of [creds.mia2027!, creds.mia!]) {
      expect(admit(jwt, holder('mia'), entryJwt, listJwt, 'member')).toEqual({ ok: false, reason: 'withdrawn' });
    }

    clock += 60;
    const back = await o.desk('POST', '/desk/vouch', { ids: ['HP-0042'] });
    const r = await redeem(codeOf(back.json.pickups[0].url), holder('mia'));
    expect(r.status).toBe(200);
    expect(payloadOf(r.json.credential).validUntil).toBe(END_2026);
    expect((await collect(holder('mia'))).json).toEqual({ vouches: [r.json.credential] });
    // The other keys' vouches were withdrawn with the row, so they are not renewed either.
    expect((await collect(holder('mia', HOMEWORK))).json).toEqual({ vouches: [] });

    // Vouched for 2027 once more, the key holding the new vouch collects 2027's.
    clock += 60;
    await o.desk('POST', '/desk/vouch', { ids: ['HP-0042'], periodEnd: END_2027 });
    const again = await collect(holder('mia'));
    expect(again.json.vouches).toHaveLength(2);
    expect(again.json.vouches[1]).toBe(r.json.credential);
    expect(again.json.vouches[0]).not.toBe(creds.mia2027);
    expect(payloadOf(again.json.vouches[0]).validUntil).toBe(END_2027);
    expect(admit(again.json.vouches[0], holder('mia'), entryJwt, await list(), 'member')).toMatchObject({ ok: true });
  });

  test('names never leave: no answer to a collect, nor any vouch in one, carries a label, group or roster id', () => {
    const texts: string[] = [];
    for (const body of seen) {
      texts.push(body);
      for (const jwt of body.match(/eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+/g) ?? []) texts.push(JSON.stringify(payloadOf(jwt)));
    }
    for (const t of texts) for (const n of NAMES) expect(t).not.toContain(n);
    expect(texts.filter((t) => t.includes(`"validUntil":"${END_2027}"`)).length).toBeGreaterThan(3);
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
    ['GET', '/desk/standing'],
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

describe('the standing', () => {
  const o = makeOffice('standing');
  const ANCHOR = anchor.toPublicKey().toString();

  test('the registry entry, the nodes and the withdrawal list, as the desk shows them', async () => {
    const r = await o.desk('GET', '/desk/standing');
    expect(r.status).toBe(200);
    const node = o.office.info().node;
    expect(r.json).toEqual({
      at: '2026-11-05T09:00:00Z',
      entry: {
        did: DID,
        kind: 'school',
        claims: ['member', 'guardian_of_member'],
        periodEnds: [END_2026, END_2027],
        steward: didKeyOfSecret(steward),
        pilotSteward: true,
        validFrom: '2026-11-04T09:00:00Z',
        validUntil: END_2027,
      },
      didDocument: `${BASE}/.well-known/did.json`,
      office: BASE,
      anchor: ANCHOR,
      node,
      nodes: [node],
      withdrawals: { url: STATUS_URL, signedAt: '2026-11-04T09:00:00Z', withdrawn: 0 },
    });
  });

  test('a withdrawal signs the list again: the standing says when, and how many places it marks', async () => {
    await o.desk('POST', '/desk/roster', { rows: ROSTER });
    await o.desk('POST', '/desk/consent', { ids: ['HP-0042'], consent: true });
    const v = await o.desk('POST', '/desk/vouch', { ids: ['HP-0042'] });
    const code = codeOf(v.json.pickups[0].url);
    for (const app of [RP, 'homework-club:online']) {
      const sk = holder('mia', app);
      const got = await o.pub('POST', `/pickup/${code}`, { proof: pickupProof({ subjectSk: sk, body: DID, code, at: clock }) });
      expect(got.status).toBe(200);
    }
    clock += 3600;
    await o.desk('POST', '/desk/withdraw', { ids: ['HP-0042'] });
    const r = await o.desk('GET', '/desk/standing');
    expect(r.json.at).toBe('2026-11-05T10:00:00Z');
    expect(r.json.withdrawals).toEqual({ url: STATUS_URL, signedAt: '2026-11-05T10:00:00Z', withdrawn: 2 });
  });

  test('a new node is named first and the old one stays honoured, until it is retired', async () => {
    const old = o.office.info().node;
    const { node } = o.office.rotateNode(anchor);
    const r = await o.desk('GET', '/desk/standing');
    expect([r.json.node, r.json.nodes]).toEqual([node, [node, old]]);
    expect(r.json.withdrawals.withdrawn).toBe(2);
    o.office.retireNode(old);
    expect((await o.desk('GET', '/desk/standing')).json.nodes).toEqual([node]);
  });

  test('it is the desk\'s alone, and carries no name', async () => {
    expect((await call(o.h, 'GET', '/desk/standing')).status).toBe(401);
    expect((await o.desk('POST', '/desk/standing', {})).status).toBe(405);
    const text = (await o.desk('GET', '/desk/standing')).text;
    for (const s of NAMES) expect(text).not.toContain(s);
  });
});

describe('the desk from another origin', () => {
  const DESK = 'https://brain.hillside.example.edu.au';
  const o = makeOffice('cors', undefined, { deskOrigins: [DESK] });
  const from = (origin: string, method: string, path: string, body?: unknown, auth?: string, extra: Record<string, string> = {}) =>
    call(o.h, method, path, body, auth, { origin, ...extra });

  test('a preflight from the desk\'s origin is answered with the route\'s methods and the bearer header', async () => {
    for (const [path, methods] of [
      ['/desk/vouch', 'POST'],
      ['/desk/roster', 'GET, POST'],
      ['/desk/standing', 'GET'],
    ]) {
      const r = await from(DESK, 'OPTIONS', path!, undefined, undefined, { 'access-control-request-method': 'POST' });
      expect(r.status).toBe(204);
      expect(r.headers.get('access-control-allow-origin')).toBe(DESK);
      expect(r.headers.get('access-control-allow-methods')).toBe(methods!);
      expect(r.headers.get('access-control-allow-headers')).toBe('authorization, content-type');
      expect(r.headers.get('vary')).toBe('Origin');
    }
  });

  test('from the desk\'s origin an answer carries the origin, and the token is still required', async () => {
    const none = await from(DESK, 'GET', '/desk/needs');
    expect([none.status, none.json.error]).toEqual([401, 'no_token']);
    expect(none.headers.get('access-control-allow-origin')).toBe(DESK);
    const bad = await from(DESK, 'GET', '/desk/needs', undefined, 'Bearer wrong');
    expect(bad.status).toBe(401);
    const ok = await from(DESK, 'POST', '/desk/roster', { rows: [{ id: 'c', kind: 'member', label: 'C' }] }, `Bearer ${o.token}`);
    expect(ok.status).toBe(200);
    expect(ok.headers.get('access-control-allow-origin')).toBe(DESK);
    expect(ok.headers.get('vary')).toBe('Origin');
  });

  test('another origin, or none, gets no CORS answer from the desk', async () => {
    for (const origin of ['https://evil.example', 'https://brain.hillside.example.edu.au:8443', 'http://brain.hillside.example.edu.au']) {
      const pre = await from(origin, 'OPTIONS', '/desk/needs');
      expect([pre.status, pre.json.error]).toEqual([403, 'origin_not_allowed']);
      expect(pre.headers.get('access-control-allow-origin')).toBeNull();
      // The office still answers the bearer; the browser keeps the answer from the page.
      const r = await from(origin, 'GET', '/desk/needs', undefined, `Bearer ${o.token}`);
      expect(r.status).toBe(200);
      expect(r.headers.get('access-control-allow-origin')).toBeNull();
    }
    const plain = makeOffice('cors-none');
    const pre = await call(plain.h, 'OPTIONS', '/desk/needs', undefined, undefined, { origin: DESK });
    expect([pre.status, pre.json.error]).toEqual([403, 'origin_not_allowed']);
    expect(pre.headers.get('access-control-allow-origin')).toBeNull();
  });

  test('the public routes stay open to every origin', async () => {
    const r = await from('https://evil.example', 'GET', '/status/1');
    expect(r.status).toBe(200);
    expect(r.headers.get('access-control-allow-origin')).toBe('*');
  });

  test('a desk origin must be an origin', () => {
    for (const bad of ['brain.example', 'https://brain.example/helm/', 'https://brain.example?x', 'ftp://brain.example', '*']) {
      expect(() => officeHandler(o.office, { deskOrigins: [bad] })).toThrow(/desk origin/);
    }
    expect(() => officeHandler(o.office, { deskOrigins: ['http://localhost:5173', DESK] })).not.toThrow();
  });
});

describe('the state file', () => {
  test('is written atomically with mode 0600, and holds the keys and roster', async () => {
    const o = makeOffice('state');
    await o.desk('POST', '/desk/roster', { rows: [{ id: 'x', kind: 'member', label: 'X' }] });
    expect(statSync(o.path).mode & 0o777).toBe(0o600);
    expect(readdirSync(dir).filter((f) => f.endsWith('.tmp'))).toEqual([]);
    const s = JSON.parse(readFileSync(o.path, 'utf8'));
    expect(s).toMatchObject({ version: 2, did: DID, baseUrl: BASE, anchor: anchor.toPublicKey().toString(), nextStatusIndex: 0 });
    expect(s.nodeKey).toMatch(/^[0-9a-f]{64}$/);
    // The current node's delegation, and the list carries it.
    const node = PrivateKey.fromString(s.nodeKey, 16).toPublicKey().toString();
    expect(s.delegations.map(readDelegation)).toEqual([{ anchor: anchor.toPublicKey().toString(), node, purpose: 'body.vouch' }]);
    expect(s).not.toHaveProperty('delegation');
    const list = verifyJwtByKid(s.statusList);
    expect(list?.signer).toBe(didKeyOf(node));
    expect(list?.payload.evidence).toEqual([{ type: 'SigningNodeDelegation', delegation: s.delegations[0] }]);
    expect(readRegistryEntry(s.registryEntry)?.steward).toBe(didKeyOfSecret(steward));
    expect(s.roster).toEqual([{ id: 'x', kind: 'member', label: 'X', consent: false }]);
  });

  test('a version 1 file, whose delegation went in every vouch, is refused', () => {
    const o = makeOffice('state-v1');
    const { delegations, ...s } = JSON.parse(readFileSync(o.path, 'utf8'));
    writeFileSync(o.path, JSON.stringify({ ...s, version: 1, delegation: delegations[0] }));
    expect(() => fileStore(o.path).load()).toThrow('version 2');
  });

  test('a steward that is the body\'s own anchor is refused', () => {
    expect(() =>
      initState({ did: DID, anchorSk: anchor, stewardSk: anchor, kind: 'school', claims: ['member'], periodEnds: [END_2026], now: NOW }),
    ).toThrow('self_registration');
  });

  test('an office not at the did\'s host is named in the DID document all the same', () => {
    const { state } = initState({
      did: 'did:web:example.org:schools:hillside',
      baseUrl: 'https://office.example.net:8443',
      anchorSk: anchor,
      stewardSk: steward,
      kind: 'school',
      claims: ['member'],
      periodEnds: [END_2026],
      now: NOW,
    });
    const path = join(dir, 'elsewhere.json');
    fileStore(path).save(state);
    const office = new Office(fileStore(path), { now: () => clock });
    expect(office.didDocumentPath()).toBe('/schools/hillside/did.json');
    expect(office.info().didDocument).toBe('https://example.org/schools/hillside/did.json');
    expect(vouchOfficeOf(office.didDocument(), 'did:web:example.org:schools:hillside')).toBe('https://office.example.net:8443');
  });

  test('an entry from a steward elsewhere is taken if it names this body and anchor', () => {
    const { state } = initState({ did: DID, anchorSk: anchor, stewardSk: steward, kind: 'club', claims: ['member'], periodEnds: [END_2026], now: NOW });
    expect(initState({ did: DID, anchorSk: anchor, entry: state.registryEntry, now: NOW }).state.registryEntry).toBe(state.registryEntry);
    expect(() => initState({ did: DID, anchorSk: key('other-anchor'), entry: state.registryEntry, now: NOW })).toThrow('anchor');
    expect(() => initState({ did: 'did:web:other.example.org', anchorSk: anchor, entry: state.registryEntry, now: NOW })).toThrow('did');
  });
});

describe('nodes', () => {
  test('a key that is not the anchor makes no new node, and changes nothing', () => {
    const o = makeOffice('rotate-wrong');
    const before = readFileSync(o.path, 'utf8');
    expect(() => o.office.rotateNode(key('other-anchor'))).toThrow('wrong_anchor');
    expect(readFileSync(o.path, 'utf8')).toBe(before);
  });

  test('the current node cannot be retired, nor a node not honoured', () => {
    const o = makeOffice('retire-refusals');
    const first = o.office.info().node;
    expect(() => o.office.retireNode(first)).toThrow('current_node');
    const { node } = o.office.rotateNode(anchor);
    expect(() => o.office.retireNode(node)).toThrow('current_node');
    expect(() => o.office.retireNode(key('stranger').toPublicKey().toString())).toThrow('unknown_node');
    expect(() => o.office.retireNode('not-a-key')).toThrow('unknown_node');
    expect(o.office.retireNode(first).nodes).toEqual([node]);
    expect(() => o.office.retireNode(first)).toThrow('unknown_node');
  });

  test('two rotations honour all three nodes until each is retired; the anchor key is not kept', () => {
    const o = makeOffice('rotate-twice');
    const a = o.office.info().node;
    const b = o.office.rotateNode(anchor).node;
    const c = o.office.rotateNode(anchor).node;
    expect(o.office.info().nodes).toEqual([c, b, a]);
    expect(o.office.retireNode(a).nodes).toEqual([c, b]);
    expect(o.office.retireNode(b).nodes).toEqual([c]);
    const s = JSON.parse(readFileSync(o.path, 'utf8'));
    expect(s.delegations).toHaveLength(1);
    expect(JSON.stringify(s)).not.toContain(anchor.toHex());
    expect(verifyJwtByKid(s.statusList)?.signer).toBe(didKeyOf(c));
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

  test('answers the desk\'s origin over HTTP', async () => {
    const o = makeOffice('server-cors');
    const desk = 'https://brain.hillside.example.edu.au';
    const server = serveOffice(o.office, { port: 0, hostname: '127.0.0.1', deskOrigins: [desk] });
    try {
      const pre = await fetch(`http://127.0.0.1:${server.port}/desk/needs`, { method: 'OPTIONS', headers: { origin: desk } });
      expect(pre.status).toBe(204);
      expect(pre.headers.get('access-control-allow-origin')).toBe(desk);
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

  test('serve takes the desk\'s origin from --desk-origin, or from $OFFICE_DESK_ORIGIN', async () => {
    const { state: made } = initState({
      did: DID,
      anchorSk: anchor,
      stewardSk: steward,
      kind: 'school',
      claims: ['member', 'guardian_of_member'],
      periodEnds: ends.split(','),
      now: Math.floor(Date.now() / 1000),
    });
    const state = join(dir, 'cli-serve-office.json');
    fileStore(state).save(made);
    const desk = 'https://brain.hillside.example.edu.au';
    const other = 'http://localhost:5173';
    const serve = async (args: string[], env: Record<string, string> = {}) => {
      const p = Bun.spawn([process.execPath, 'bodies/office/cli.ts', 'serve', '--state', state, '--port', '0', ...args], {
        cwd: join(import.meta.dir, '..'),
        env: { ...process.env, ...env },
        stdout: 'pipe',
        stderr: 'pipe',
      });
      const reader = p.stdout.getReader();
      let out = '';
      // The last line serve prints says where the desk is served from.
      while (!/ desk from .*\n/.test(out)) {
        const { value, done } = await reader.read();
        if (done) break;
        out += new TextDecoder().decode(value);
      }
      return { p, base: /listening on (\S+)/.exec(out)![1]!, out };
    };
    const preflight = (base: string, origin: string) => fetch(`${base}/desk/needs`, { method: 'OPTIONS', headers: { origin } });

    const a = await serve(['--desk-origin', `${desk},${other}`]);
    try {
      expect(a.out).toContain(`desk from ${desk}, ${other}`);
      expect((await preflight(a.base, desk)).headers.get('access-control-allow-origin')).toBe(desk);
      expect((await preflight(a.base, other)).headers.get('access-control-allow-origin')).toBe(other);
      expect((await preflight(a.base, 'https://evil.example')).status).toBe(403);
    } finally {
      a.p.kill();
    }
    const b = await serve([], { OFFICE_DESK_ORIGIN: desk });
    try {
      expect((await preflight(b.base, desk)).headers.get('access-control-allow-origin')).toBe(desk);
    } finally {
      b.p.kill();
    }
    const bad = cli('serve', '--state', state, '--port', '0', '--desk-origin', 'https://brain.example/helm/');
    expect(bad.code).not.toBe(0);
    expect(bad.err).toContain('desk origin');
  });

  test('rotate-node with the anchor key file, then retire-node for the old node', () => {
    const anchorFile = join(dir, 'cli3-anchor.key');
    const otherFile = join(dir, 'cli3-other.key');
    writeFileSync(anchorFile, anchor.toHex(), { mode: 0o600 });
    writeFileSync(otherFile, key('other-anchor').toHex(), { mode: 0o600 });
    const { state: made } = initState({
      did: DID,
      anchorSk: anchor,
      stewardSk: steward,
      kind: 'school',
      claims: ['member', 'guardian_of_member'],
      periodEnds: ends.split(','),
      now: Math.floor(Date.now() / 1000),
    });
    const state = join(dir, 'cli3-office.json');
    fileStore(state).save(made);
    const old = new Office(fileStore(state)).info().node;

    expect(cli('rotate-node', '--state', state).code).not.toBe(0);
    const wrong = cli('rotate-node', '--state', state, '--anchor-key', otherFile);
    expect(wrong.code).not.toBe(0);
    expect(wrong.err).toContain('wrong_anchor');

    const run = cli('rotate-node', '--state', state, '--anchor-key', anchorFile);
    expect(run.code).toBe(0);
    const info = new Office(fileStore(state)).info();
    expect(info.node).not.toBe(old);
    expect(info.nodes).toEqual([info.node, old]);
    expect(run.out).toContain(info.node);
    expect(run.out).toContain(`retire-node ${old}`);
    expect(readFileSync(state, 'utf8')).not.toContain(anchor.toHex());

    const none = cli('retire-node', '--state', state);
    expect(none.code).not.toBe(0);
    expect(none.err).toContain(old);
    const current = cli('retire-node', '--state', state, info.node);
    expect(current.code).not.toBe(0);
    expect(current.err).toContain('current_node');
    const retire = cli('retire-node', '--state', state, old);
    expect(retire.code).toBe(0);
    expect(retire.out).toContain('node_not_delegated');
    expect(new Office(fileStore(state)).info().nodes).toEqual([info.node]);
  });
});
