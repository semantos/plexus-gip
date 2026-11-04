/**
 * Any body as attestor (`src/bodies/`): registry, delegated node, one-claim
 * vouches about pairwise keys, presentations and the offline gate.
 */
import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { PrivateKey } from '@bsv/sdk';
import {
  BODY_KINDS,
  BODY_REFUSALS,
  BODY_VOUCH_PURPOSE,
  type BodyClaim,
  type BodyKind,
  type BodyRefusal,
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
  const list = (revoked: number[] = [], signer = node, d = delegation) =>
    issueStatusList(signer, { issuer: spec.did, delegation: d, url: statusList, revoked, validFrom: NOW - 3600 });
  return { spec, anchor, node, delegation, statusList, entryJwt, entry, list };
}

type Body = ReturnType<typeof body>;

/** A holder's relationship key for the kids' world. */
const holder = (label: string) => relationshipKey(key(`${label}/root`), RP);

function vouch(b: Body, subjectSk: PrivateKey, over: Partial<Parameters<typeof issueVouch>[0]> = {}): string {
  return issueVouch({
    nodeSk: b.node,
    delegation: b.delegation,
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

  test('node_not_delegated: a delegation signed by someone other than the anchor', () => {
    const forged = delegateSigner(impostor, pub(b.node), BODY_VOUCH_PURPOSE);
    const c = vouch(b, mia, { delegation: forged, entry: { ...b.entry, anchor: pub(impostor) } });
    expect(verifyPresentation(show(c, mia), gate(b))).toEqual(refused('node_not_delegated'));
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

  test('no_status_list: none held, or one not signed by the body', () => {
    expect(verifyPresentation(ok, gate(b, { statusLists: {} }))).toEqual(refused('no_status_list'));
    const rogue = key('rogue-node');
    const rogueList = b.list([], rogue, delegateSigner(impostor, pub(rogue), BODY_VOUCH_PURPOSE));
    expect(verifyPresentation(ok, gate(b, { statusLists: { [b.statusList]: rogueList } }))).toEqual(refused('no_status_list'));
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
      'node_not_delegated',
      'claim_not_allowed',
      'not_yet_valid',
      'expired',
      'no_status_list',
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

  test('a delegation that does not verify, is not from the anchor, is not for this node, or has the wrong purpose', () => {
    const tampered = { ...b.delegation, signature: delegateSigner(b.anchor, pub(key('other-node')), BODY_VOUCH_PURPOSE).signature };
    expect(() => vouch(b, mia, { delegation: tampered })).toThrow('does not verify');
    expect(() => vouch(b, mia, { delegation: delegateSigner(impostor, pub(b.node), BODY_VOUCH_PURPOSE) })).toThrow('not from the registered anchor');
    expect(() => vouch(b, mia, { delegation: delegateSigner(b.anchor, pub(key('other-node')), BODY_VOUCH_PURPOSE) })).toThrow('not for this node');
    expect(() => vouch(b, mia, { delegation: delegateSigner(b.anchor, pub(b.node), 'kin.vouch') })).toThrow('purpose');
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

describe('node rotation', () => {
  test('a new node works, the old node\'s credentials still verify, a forged delegation does not', () => {
    const b = body(SCHOOL);
    const mia = holder('mia');
    const oldCred = vouch(b, mia, { statusIndex: 3 });
    const node2 = key(`${SCHOOL.label}/node-2`);
    const delegation2 = delegateSigner(b.anchor, pub(node2), BODY_VOUCH_PURPOSE);
    const theo = holder('theo');
    const newCred = vouch(b, theo, { nodeSk: node2, delegation: delegation2, statusIndex: 4 });
    // After rotation the new node publishes the list.
    const lists = { [b.statusList]: b.list([], node2, delegation2) };
    expect(verifyPresentation(show(newCred, theo), gate(b, { statusLists: lists })).ok).toBe(true);
    expect(verifyPresentation(show(oldCred, mia), gate(b, { statusLists: lists })).ok).toBe(true);

    const evilNode = key('evil-node');
    const forged = delegateSigner(impostor, pub(evilNode), BODY_VOUCH_PURPOSE);
    const forgedCred = vouch(b, mia, { nodeSk: evilNode, delegation: forged, entry: { ...b.entry, anchor: pub(impostor) } });
    expect(verifyPresentation(show(forgedCred, mia), gate(b, { statusLists: lists }))).toEqual(refused('node_not_delegated'));
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
