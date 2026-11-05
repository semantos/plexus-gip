/**
 * Any body as attestor (`src/bodies/`): registry, delegated node, one-claim
 * vouches about pairwise keys, presentations and the offline gate.
 */
import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { PrivateKey } from '@bsv/sdk';
import {
  type Association,
  BODY_KINDS,
  BODY_REFUSALS,
  BODY_VOUCH_PURPOSE,
  type BodyClaim,
  type BodyKind,
  type BodyRefusal,
  DELEGATION_EVIDENCE_TYPE,
  EDGE_CREATION,
  type RegistryEntry,
  type VerifyPresentationOptions,
  delegateSigner,
  didKeyOf,
  didKeyOfSecret,
  fromB64url,
  fromUtf8,
  issueRegistryEntry,
  issueStatusList,
  issueVouch,
  present,
  readRegistryEntry,
  relationshipKey,
  signJwt,
  verifyPresentation,
} from '../src';

const key = (label: string): PrivateKey =>
  PrivateKey.fromString(createHash('sha256').update(`gip-v2-bodies-test/${label}`).digest('hex'), 16);
const pub = (k: PrivateKey): string => k.toPublicKey().toString();
const payloadOf = (jwt: string) => JSON.parse(fromUtf8(fromB64url(jwt.split('.')[1]!)));

const NOW = Date.UTC(2026, 10, 4, 12) / 1000; // 2026-11-04T12:00:00Z
const END_2026 = '2026-12-31T23:59:59Z';
const END_2027 = '2027-12-31T23:59:59Z';
const at = (iso: string): number => Date.parse(iso) / 1000;
const RP = 'kids-world:gem-island';
const NONCE = 'challenge-0001';

/** The school's own records. Nothing here may reach a credential. */
const RECORDS = {
  student: { given: 'Mia', family: 'Ellis', birthdate: '2016-03-04', studentNumber: 'HP-0042', enrolled: true },
  guardian: { given: 'Sam', family: 'Ellis', guardianOf: 'HP-0042' },
};
const PERSONAL = ['Mia', 'Sam', 'Ellis', '2016-03-04', 'HP-0042'];

const steward = key('steward');
const STEWARDS = new Set([didKeyOfSecret(steward)]);
const impostor = key('impostor');

interface BodySpec {
  label: string;
  did: string;
  host: string;
  kind: BodyKind;
  claims: BodyClaim[];
}
const SCHOOL: BodySpec = {
  label: 'hillside',
  did: 'did:web:hillside.example.edu.au',
  host: 'hillside.example.edu.au',
  kind: 'school',
  claims: ['member', 'guardian_of_member'],
};
const SCOUTS: BodySpec = {
  label: '1st-hillside-scouts',
  did: 'did:web:1st-hillside.scouts.example.org.au',
  host: '1st-hillside.scouts.example.org.au',
  kind: 'scouts',
  claims: ['member', 'guardian_of_member', 'helper'],
};

/** A registered body with a delegated node. */
function body(spec: BodySpec, over: { validUntil?: string } = {}) {
  const anchor = key(`${spec.label}/anchor`);
  const node = key(`${spec.label}/node-1`);
  const delegation = delegateSigner(anchor, pub(node), BODY_VOUCH_PURPOSE);
  const statusList = `https://${spec.host}/status/1`;
  const entryJwt = issueRegistryEntry(steward, {
    did: spec.did,
    anchor: pub(anchor),
    kind: spec.kind,
    claims: spec.claims,
    periodEnds: [END_2026, END_2027],
    statusList,
    validFrom: NOW - 30 * 86400,
    validUntil: over.validUntil ?? END_2027,
  });
  const entry = readRegistryEntry(entryJwt);
  if (entry === null) throw new Error('entry did not read back');
  const list = (revoked: number[] = [], signer = node, delegations = [delegation]) =>
    issueStatusList(signer, { issuer: spec.did, delegations, url: statusList, revoked, validFrom: NOW - 3600 });
  return { spec, anchor, node, delegation, statusList, entryJwt, entry, list };
}

type Body = ReturnType<typeof body>;

/** Delegations as a list carries them in `evidence`. */
const asEvidence = (...ds: Association[]) => ds.map((delegation) => ({ type: DELEGATION_EVIDENCE_TYPE, delegation }));

/** A list signed as given, whatever its evidence says: issueStatusList refuses most of these. */
function rawList(b: Body, signer: PrivateKey, evidence: unknown): string {
  const { evidence: _, ...p } = payloadOf(b.list());
  return signJwt(evidence === undefined ? p : { ...p, evidence }, signer);
}

/** The gate holding one list for the body. */
const holding = (b: Body, listJwt: string) => gate(b, { statusLists: { [b.statusList]: listJwt } });

/** A holder's relationship key for the kids' world. */
const holder = (label: string) => relationshipKey(key(`${label}/root`), RP);

function vouch(b: Body, subjectSk: PrivateKey, over: Partial<Parameters<typeof issueVouch>[0]> = {}): string {
  return issueVouch({
    nodeSk: b.node,
    entry: b.entry,
    subject: didKeyOfSecret(subjectSk),
    claim: 'member',
    statusIndex: 7,
    validFrom: NOW - 3600,
    validUntil: END_2026,
    ...over,
  });
}

function gate(b: Body, over: Partial<VerifyPresentationOptions> = {}): VerifyPresentationOptions {
  return {
    audience: RP,
    nonce: NONCE,
    stewards: STEWARDS,
    registryEntries: [b.entryJwt],
    statusLists: { [b.statusList]: b.list() },
    now: NOW,
    require: 'member',
    ...over,
  };
}

const show = (credentialJwt: string, subjectSk: PrivateKey, at = NOW, nonce = NONCE, audience = RP) =>
  present({ credentialJwt, subjectSk, audience, nonce, at });

const refused = (reason: BodyRefusal) => ({ ok: false as const, reason });

describe('any body, no code change', () => {
  test('a school and a scout group both vouch, and the gate accepts both', () => {
    for (const spec of [SCHOOL, SCOUTS]) {
      const b = body(spec);
      const child = holder(`${spec.label}/child`);
      const parent = holder(`${spec.label}/parent`);
      const childCred = vouch(b, child, { claim: 'member', statusIndex: 1 });
      const parentCred = vouch(b, parent, { claim: 'guardian_of_member', statusIndex: 2 });
      expect(verifyPresentation(show(childCred, child), gate(b))).toEqual({
        ok: true,
        body: { did: spec.did, kind: spec.kind },
        claim: 'member',
        subject: didKeyOfSecret(child),
      });
      expect(verifyPresentation(show(parentCred, parent), gate(b, { require: 'guardian_of_member' }))).toEqual({
        ok: true,
        body: { did: spec.did, kind: spec.kind },
        claim: 'guardian_of_member',
        subject: didKeyOfSecret(parent),
      });
    }
  });

  test('every kind of body goes through the same path', () => {
    for (const kind of BODY_KINDS) {
      const b = body({ label: `kind-${kind}`, did: `did:web:${kind}.example.org`, host: `${kind}.example.org`, kind, claims: ['helper'] });
      const adult = holder(`kind-${kind}/adult`);
      const r = verifyPresentation(show(vouch(b, adult, { claim: 'helper' }), adult), gate(b, { require: 'helper' }));
      expect(r).toMatchObject({ ok: true, body: { kind } });
    }
  });
});

describe('the gate refuses, each for its own reason', () => {
  const b = body(SCHOOL);
  const mia = holder('mia');
  const cred = vouch(b, mia);
  const ok = show(cred, mia);

  test('the base case is accepted', () => {
    expect(verifyPresentation(ok, gate(b)).ok).toBe(true);
  });

  test('bad_presentation: malformed, edited, or a credential passed off as a presentation', () => {
    expect(verifyPresentation('not-a-jwt', gate(b))).toEqual(refused('bad_presentation'));
    const [h, , s] = ok.split('.');
    const edited = Buffer.from(JSON.stringify({ ...payloadOf(ok), nonce: 'challenge-0002' })).toString('base64url');
    expect(verifyPresentation(`${h}.${edited}.${s}`, gate(b, { nonce: 'challenge-0002' }))).toEqual(refused('bad_presentation'));
    expect(verifyPresentation(cred, gate(b))).toEqual(refused('bad_presentation'));
  });

  test('wrong_audience', () => {
    expect(verifyPresentation(ok, gate(b, { audience: 'other-platform' }))).toEqual(refused('wrong_audience'));
  });

  test('wrong_nonce', () => {
    expect(verifyPresentation(ok, gate(b, { nonce: 'challenge-0002' }))).toEqual(refused('wrong_nonce'));
  });

  test('stale: more than 300 s either side', () => {
    expect(verifyPresentation(ok, gate(b, { now: NOW + 300 })).ok).toBe(true);
    expect(verifyPresentation(ok, gate(b, { now: NOW + 301 }))).toEqual(refused('stale'));
    expect(verifyPresentation(ok, gate(b, { now: NOW - 301 }))).toEqual(refused('stale'));
  });

  test('bad_credential: edited, or carrying more than one claim', () => {
    const [h, , s] = cred.split('.');
    const p = payloadOf(cred);
    p.credentialSubject = { id: p.credentialSubject.id, age_over_18: true };
    const edited = `${h}.${Buffer.from(JSON.stringify(p)).toString('base64url')}.${s}`;
    expect(verifyPresentation(show(edited, mia), gate(b))).toEqual(refused('bad_credential'));
    const twoTerms = payloadOf(cred);
    twoTerms.credentialSubject.given = 'Mia';
    expect(verifyPresentation(show(signJwt(twoTerms, b.node), mia), gate(b))).toEqual(refused('bad_credential'));
  });

  test('bad_credential: a vouch carrying evidence, even the node\'s own delegation as v1 put it', () => {
    expect(payloadOf(cred)).not.toHaveProperty('evidence');
    for (const evidence of [asEvidence(b.delegation), [], null]) {
      const v1 = signJwt({ ...payloadOf(cred), evidence }, b.node);
      expect(verifyPresentation(show(v1, mia), gate(b))).toEqual(refused('bad_credential'));
    }
  });

  test('subject_mismatch: someone else presents the credential', () => {
    const thief = holder('thief');
    expect(verifyPresentation(show(cred, thief), gate(b))).toEqual(refused('subject_mismatch'));
  });

  test('not_registered: no entry, an untrusted steward, an entry out of date, a body registered by itself', () => {
    expect(verifyPresentation(ok, gate(b, { registryEntries: [] }))).toEqual(refused('not_registered'));
    expect(verifyPresentation(ok, gate(b, { stewards: new Set([didKeyOfSecret(impostor)]) }))).toEqual(refused('not_registered'));
    const lapsed = body(SCHOOL, { validUntil: '2026-11-01T00:00:00Z' });
    expect(verifyPresentation(ok, gate(b, { registryEntries: [lapsed.entryJwt] }))).toEqual(refused('not_registered'));
    // The body's anchor signs its own entry, and is even put in the trusted set.
    const selfEntry = signJwt({ ...payloadOf(b.entryJwt), issuer: didKeyOfSecret(b.anchor) }, b.anchor);
    expect(readRegistryEntry(selfEntry)).toBeNull();
    const selfGate = gate(b, { registryEntries: [selfEntry], stewards: new Set([didKeyOfSecret(b.anchor)]) });
    expect(verifyPresentation(ok, selfGate)).toEqual(refused('not_registered'));
  });

  test('no_status_list: none held, or held only under another URL', () => {
    expect(verifyPresentation(ok, gate(b, { statusLists: {} }))).toEqual(refused('no_status_list'));
    const elsewhere = { 'https://hillside.example.edu.au/status/2': b.list() };
    expect(verifyPresentation(ok, gate(b, { statusLists: elsewhere }))).toEqual(refused('no_status_list'));
  });

  test('no_status_list: a list that is malformed, edited, or not a status list', () => {
    expect(verifyPresentation(ok, holding(b, 'not-a-jwt'))).toEqual(refused('no_status_list'));
    const [h, , s] = b.list([7]).split('.');
    const cleared = payloadOf(b.list([7]));
    cleared.credentialSubject.encodedList = payloadOf(b.list()).credentialSubject.encodedList;
    expect(verifyPresentation(ok, holding(b, `${h}.${Buffer.from(JSON.stringify(cleared)).toString('base64url')}.${s}`))).toEqual(
      refused('no_status_list'),
    );
    expect(verifyPresentation(ok, holding(b, b.entryJwt))).toEqual(refused('no_status_list'));
    const later = signJwt({ ...payloadOf(b.list()), validFrom: '2026-11-05T00:00:00Z' }, b.node);
    expect(verifyPresentation(ok, holding(b, later))).toEqual(refused('no_status_list'));
  });

  test('no_status_list: a list whose signer the list\'s own evidence does not delegate from the anchor', () => {
    const rogue = key('rogue-node');
    const node2 = key(`${SCHOOL.label}/node-2`);
    const lists = [
      // A node the impostor delegated, carrying that delegation.
      b.list([], rogue, [delegateSigner(impostor, pub(rogue), BODY_VOUCH_PURPOSE)]),
      // A node the anchor did delegate, but its delegation is not on the list.
      rawList(b, node2, asEvidence(b.delegation)),
      // The right node, delegated for another purpose.
      rawList(b, b.node, asEvidence(delegateSigner(b.anchor, pub(b.node), 'kin.vouch'))),
      // The right node, with no evidence, or evidence that is not a list of delegations.
      rawList(b, b.node, undefined),
      rawList(b, b.node, { type: DELEGATION_EVIDENCE_TYPE, delegation: b.delegation }),
      rawList(b, b.node, [{ type: 'Bond', delegation: b.delegation }]),
    ];
    for (const l of lists) expect(verifyPresentation(ok, holding(b, l))).toEqual(refused('no_status_list'));
    expect(verifyPresentation(ok, holding(b, rawList(b, b.node, asEvidence(b.delegation)))).ok).toBe(true);
  });

  test('no_status_list: the vouch points at a list other than the entry\'s', () => {
    const other = 'https://hillside.example.edu.au/status/2';
    const c = vouch(b, mia, { entry: { ...b.entry, statusList: other } });
    const lists = { [b.statusList]: b.list(), [other]: b.list() };
    expect(verifyPresentation(show(c, mia), gate(b, { statusLists: lists }))).toEqual(refused('no_status_list'));
  });

  test('no_status_list comes before node_not_delegated, claim_not_allowed and the dates', () => {
    const rogue = key('rogue-node');
    const roguish = issueVouch({
      nodeSk: rogue,
      entry: { ...b.entry, periodEnds: ['2026-11-01T00:00:00Z'] },
      subject: didKeyOfSecret(mia),
      claim: 'member',
      statusIndex: 7,
      validFrom: '2026-10-01T00:00:00Z',
      validUntil: '2026-11-01T00:00:00Z',
    });
    expect(verifyPresentation(show(roguish, mia), gate(b, { statusLists: {} }))).toEqual(refused('no_status_list'));
    expect(verifyPresentation(show(roguish, mia), gate(b))).toEqual(refused('node_not_delegated'));
  });

  test('node_not_delegated: a vouch from a node the list does not carry', () => {
    const rogue = key('rogue-node');
    const c = vouch(b, mia, { nodeSk: rogue });
    expect(verifyPresentation(show(c, mia), gate(b))).toEqual(refused('node_not_delegated'));
  });

  test('node_not_delegated: a delegation on the list from another anchor, or for another purpose, does not count', () => {
    const rogue = key('rogue-node');
    const c = vouch(b, mia, { nodeSk: rogue });
    const l = rawList(
      b,
      b.node,
      asEvidence(b.delegation, delegateSigner(impostor, pub(rogue), BODY_VOUCH_PURPOSE), delegateSigner(b.anchor, pub(rogue), 'kin.vouch')),
    );
    expect(verifyPresentation(show(c, mia), holding(b, l))).toEqual(refused('node_not_delegated'));
  });

  test('node_not_delegated: a node whose delegation was dropped; the remaining node still passes', () => {
    const node2 = key(`${SCHOOL.label}/node-2`);
    const d2 = delegateSigner(b.anchor, pub(node2), BODY_VOUCH_PURPOSE);
    const theo = holder('theo');
    const fromNode2 = vouch(b, theo, { nodeSk: node2, statusIndex: 9 });
    const dropped = b.list([], node2, [d2]);
    expect(verifyPresentation(ok, holding(b, dropped))).toEqual(refused('node_not_delegated'));
    expect(verifyPresentation(show(fromNode2, theo), holding(b, dropped)).ok).toBe(true);
  });

  test('node_not_delegated comes before claim_not_allowed and the dates', () => {
    const rogue = key('rogue-node');
    const c = issueVouch({
      nodeSk: rogue,
      entry: { ...b.entry, claims: ['age_over_18'], periodEnds: ['2026-11-01T00:00:00Z'] },
      subject: didKeyOfSecret(mia),
      claim: 'age_over_18',
      statusIndex: 7,
      validFrom: '2026-10-01T00:00:00Z',
      validUntil: '2026-11-01T00:00:00Z',
    });
    expect(verifyPresentation(show(c, mia), gate(b, { require: 'age_over_18' }))).toEqual(refused('node_not_delegated'));
  });

  test('claim_not_allowed: a claim, or an expiry, the registry does not list', () => {
    const wider = { ...b.entry, claims: [...b.entry.claims, 'age_over_18' as const] };
    const c = vouch(b, mia, { entry: wider, claim: 'age_over_18' });
    expect(verifyPresentation(show(c, mia), gate(b, { require: 'age_over_18' }))).toEqual(refused('claim_not_allowed'));
    const birthday = '2027-03-04T00:00:00Z';
    const d = vouch(b, mia, { entry: { ...b.entry, periodEnds: [birthday] }, validUntil: birthday });
    expect(verifyPresentation(show(d, mia), gate(b))).toEqual(refused('claim_not_allowed'));
  });

  test('not_yet_valid', () => {
    const c = vouch(b, mia, { validFrom: NOW + 3600 });
    expect(verifyPresentation(show(c, mia), gate(b))).toEqual(refused('not_yet_valid'));
  });

  test('expired: past its period end while the body is still registered', () => {
    const later = at(END_2026) + 60;
    expect(verifyPresentation(show(cred, mia, later), gate(b, { now: later }))).toEqual(refused('expired'));
  });

  test('withdrawn: the withdrawn index is refused, its sibling is not', () => {
    const sibling = holder('mia-sibling');
    const sibCred = vouch(b, sibling, { statusIndex: 8 });
    const lists = { [b.statusList]: b.list([7]) };
    expect(verifyPresentation(ok, gate(b, { statusLists: lists }))).toEqual(refused('withdrawn'));
    expect(verifyPresentation(show(sibCred, sibling), gate(b, { statusLists: lists })).ok).toBe(true);
  });

  test('missing_claim', () => {
    expect(verifyPresentation(ok, gate(b, { require: 'age_over_13' }))).toEqual(refused('missing_claim'));
  });

  test('the refusals are the documented list, in order', () => {
    expect(BODY_REFUSALS).toEqual([
      'bad_presentation',
      'wrong_audience',
      'wrong_nonce',
      'stale',
      'bad_credential',
      'subject_mismatch',
      'not_registered',
      'no_status_list',
      'node_not_delegated',
      'claim_not_allowed',
      'not_yet_valid',
      'expired',
      'withdrawn',
      'missing_claim',
    ]);
  });
});

describe('issuing refuses', () => {
  const b = body(SCHOOL);
  const mia = holder('mia');

  test('a claim the registry does not allow', () => {
    expect(() => vouch(b, mia, { claim: 'age_over_18' })).toThrow('claim_not_allowed');
  });

  test('an expiry that is not a published period end, such as a birthday', () => {
    expect(() => vouch(b, mia, { validUntil: '2027-03-04T00:00:00Z' })).toThrow('not_a_period_end');
    expect(() => vouch(b, mia, { validUntil: at(END_2026) + 1 })).toThrow('not_a_period_end');
    expect(() => vouch(b, mia, { validUntil: at(END_2026) })).not.toThrow();
  });

  test('a vouch carries no delegation: that travels on the list', () => {
    const p = payloadOf(vouch(b, mia));
    expect(p).not.toHaveProperty('evidence');
    expect(Object.keys(p)).toEqual(['@context', 'type', 'issuer', 'validFrom', 'validUntil', 'credentialSubject', 'credentialStatus']);
  });

  test('a list carries every delegation given, in order, as evidence', () => {
    const node2 = key(`${SCHOOL.label}/node-2`);
    const d2 = delegateSigner(b.anchor, pub(node2), BODY_VOUCH_PURPOSE);
    expect(payloadOf(b.list([], node2, [d2, b.delegation])).evidence).toEqual(asEvidence(d2, b.delegation));
  });

  test('a list whose delegations do not verify, have the wrong purpose, leave out its signer, mix anchors or repeat a node', () => {
    const node2 = key(`${SCHOOL.label}/node-2`);
    const d2 = delegateSigner(b.anchor, pub(node2), BODY_VOUCH_PURPOSE);
    const tampered = { ...b.delegation, signature: d2.signature };
    expect(() => b.list([], b.node, [])).toThrow('bad_delegation');
    expect(() => b.list([], b.node, [tampered])).toThrow('does not verify');
    expect(() => b.list([], b.node, [delegateSigner(b.anchor, pub(b.node), 'kin.vouch')])).toThrow('purpose');
    expect(() => b.list([], b.node, [d2])).toThrow('signing node');
    expect(() => b.list([], b.node, [b.delegation, delegateSigner(impostor, pub(node2), BODY_VOUCH_PURPOSE)])).toThrow('one anchor');
    expect(() => b.list([], b.node, [b.delegation, b.delegation])).toThrow('one delegation per node');
  });

  test('a subject that is not a did:key, and an index off the list', () => {
    expect(() => vouch(b, mia, { subject: 'did:web:mia.example' })).toThrow('bad_subject');
    expect(() => vouch(b, mia, { statusIndex: 131072 })).toThrow('bad_status_index');
  });

  test('a steward registering itself, and a kind outside the list', () => {
    const base = {
      did: 'did:web:self.example.org',
      kind: 'club' as const,
      claims: ['member' as const],
      periodEnds: [END_2026],
      statusList: 'https://self.example.org/status/1',
      validFrom: NOW,
      validUntil: END_2027,
    };
    expect(() => issueRegistryEntry(steward, { ...base, anchor: pub(steward) })).toThrow('self_registration');
    expect(() => issueRegistryEntry(steward, { ...base, anchor: pub(key('club')), kind: 'cartel' as BodyKind })).toThrow('kind');
  });
});

describe('pairwise identifiers', () => {
  test('one holder root gives a different subject to each relying party', () => {
    const root = key('mia/root');
    const forWorld = relationshipKey(root, 'kids-world:gem-island');
    const forOther = relationshipKey(root, 'homework-club:online');
    expect(didKeyOfSecret(forWorld)).not.toBe(didKeyOfSecret(forOther));
    expect(didKeyOfSecret(forWorld)).not.toBe(didKeyOf(root.toPublicKey()));
    expect(didKeyOfSecret(relationshipKey(root, 'kids-world:gem-island'))).toBe(didKeyOfSecret(forWorld));
  });

  test('derived as Plexus kdf-v1 derives a child', () => {
    const root = key('mia/root');
    const tag = createHash('sha256').update('kids-world:gem-island').digest('hex').slice(0, 16);
    const expected = root.deriveChild(root.toPublicKey(), `relationship-${tag}:${EDGE_CREATION}:0`);
    expect(relationshipKey(root, 'kids-world:gem-island').toHex()).toBe(expected.toHex());
  });
});

describe('node rotation and withdrawal', () => {
  const b = body(SCHOOL);
  const mia = holder('mia');
  const theo = holder('theo');
  const oldCred = vouch(b, mia, { statusIndex: 3 });
  const node2 = key(`${SCHOOL.label}/node-2`);
  const d2 = delegateSigner(b.anchor, pub(node2), BODY_VOUCH_PURPOSE);
  const newCred = vouch(b, theo, { nodeSk: node2, statusIndex: 4 });

  test('the new node signs the list, which carries both delegations: both nodes\' vouches pass', () => {
    const both = b.list([], node2, [d2, b.delegation]);
    expect(verifyPresentation(show(newCred, theo), holding(b, both)).ok).toBe(true);
    expect(verifyPresentation(show(oldCred, mia), holding(b, both)).ok).toBe(true);
    // The old node may still sign it while both are honoured.
    expect(verifyPresentation(show(newCred, theo), holding(b, b.list([], b.node, [b.delegation, d2]))).ok).toBe(true);
    // Withdrawal still works per vouch, whichever node signed it.
    const lists = b.list([3], node2, [d2, b.delegation]);
    expect(verifyPresentation(show(oldCred, mia), holding(b, lists))).toEqual(refused('withdrawn'));
    expect(verifyPresentation(show(newCred, theo), holding(b, lists)).ok).toBe(true);
  });

  test('withdrawing the old node: its delegation is dropped and the list signed again; its vouches fail, the new node\'s pass', () => {
    const retired = b.list([], node2, [d2]);
    expect(verifyPresentation(show(oldCred, mia), holding(b, retired))).toEqual(refused('node_not_delegated'));
    expect(verifyPresentation(show(newCred, theo), holding(b, retired)).ok).toBe(true);
    // The retired node cannot sign the list any more: it is not on it.
    const byOld = rawList(b, b.node, asEvidence(d2));
    expect(verifyPresentation(show(newCred, theo), holding(b, byOld))).toEqual(refused('no_status_list'));
  });

  test('a node an impostor delegated is refused, even on a list it signed itself', () => {
    const evilNode = key('evil-node');
    const forged = delegateSigner(impostor, pub(evilNode), BODY_VOUCH_PURPOSE);
    const forgedCred = vouch(b, mia, { nodeSk: evilNode });
    const both = b.list([], node2, [d2, b.delegation]);
    expect(verifyPresentation(show(forgedCred, mia), holding(b, both))).toEqual(refused('node_not_delegated'));
    const own = b.list([], evilNode, [forged]);
    expect(verifyPresentation(show(forgedCred, mia), holding(b, own))).toEqual(refused('no_status_list'));
  });
});

describe('privacy', () => {
  test('no payload carries a name, a birthdate or a record number from the school records', () => {
    const b = body(SCHOOL);
    const child = holder('mia');
    const parent = holder('sam');
    // The registrar reads the records and decides; only the decision is signed.
    const childCred = RECORDS.student.enrolled ? vouch(b, child, { statusIndex: 1 }) : null;
    const parentCred = RECORDS.guardian.guardianOf === RECORDS.student.studentNumber
      ? vouch(b, parent, { claim: 'guardian_of_member', statusIndex: 2 })
      : null;
    expect(childCred).not.toBeNull();
    expect(parentCred).not.toBeNull();
    const jwts = [b.entryJwt, b.list([1]), childCred!, parentCred!, show(childCred!, child), show(parentCred!, parent)];
    for (const jwt of jwts) {
      const text = JSON.stringify(payloadOf(jwt)) + JSON.stringify(payloadOf(jwt).vp ? payloadOf(payloadOf(jwt).vp) : {});
      for (const s of PERSONAL) expect(text).not.toContain(s);
      expect(text).not.toMatch(/birth|name/i);
    }
  });

  test('the registry entry reads back as issued', () => {
    const b = body(SCHOOL);
    expect(b.entry).toEqual({
      did: SCHOOL.did,
      anchor: pub(b.anchor),
      kind: 'school',
      claims: ['member', 'guardian_of_member'],
      periodEnds: [END_2026, END_2027],
      statusList: b.statusList,
      validFrom: '2026-10-05T12:00:00Z',
      validUntil: END_2027,
      steward: didKeyOfSecret(steward),
    } satisfies RegistryEntry);
  });
});
