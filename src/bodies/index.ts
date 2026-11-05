/**
 * Any accountable body as attestor: a school, club, scout group, parish,
 * sports club, employer or professional body.
 *
 * A body confirms one fact about a member once, from its own records, and
 * signs a credential. The member keeps it in their own wallet. Nothing in it
 * names them: no name, no birthdate, no record number. A relying platform
 * sends a one-time challenge, the holder's key signs it, and the platform
 * checks three things offline. It never asks the body about a member.
 *
 *   1. The chain of signatures: holder, credential, signing node, body anchor.
 *   2. The body's standing in a published registry ("who counts"), signed by a
 *      steward the platform trusts. A body that registers itself counts for
 *      nothing.
 *   3. The body's withdrawal list, fetched whole, so the fetch does not say
 *      which member was checked. It also carries the anchor's delegation of
 *      each node the body honours, which is how step 1 reaches the anchor.
 *
 * Standards: W3C VC Data Model 2.0 as a JWT with ES256K, Bitstring Status List
 * 1.0, did:web for the body, did:key for the member, with a different did:key
 * for each relationship ({@link relationshipKey}).
 *
 * The body's anchor (its Plexus page-0) never signs a credential. It delegates
 * a signing node with `delegateSigner(anchorSk, nodePub, BODY_VOUCH_PURPOSE)`.
 * The delegations travel on the withdrawal list, as its evidence: one for each
 * node the body still honours, and the list is signed by one of them. A vouch
 * carries none, so a few of them fit one QR code. Rotation puts the new node's
 * delegation on the list beside the old one; withdrawing a node takes its
 * delegation off, and every vouch it signed fails at the next download.
 *
 * One claim per credential, so a holder discloses one fact at a time.
 */
import { createHash } from 'node:crypto';
import type { PrivateKey, PublicKey } from '@bsv/sdk';
import type { Association } from '../associations';
import { readDelegation } from '../social/delegation';
import { WireError, fromHex, hex } from './bytes';
import { didKeyFromPublicKey, publicKeyFromDidKey } from './didkey';
import { type SignedJwt, VC_CONTEXT, didKeyOfSecret, signJwt, verifyJwt, verifyJwtByKid } from './jws';
import { STATUS_LIST_BITS, decodeStatusList, encodeStatusList, statusListBit } from './statuslist';

export { WireError, b64url, base58btc, fromB64url, fromBase58btc, fromHex, fromUtf8, hex, utf8 } from './bytes';
export { didKeyFromPublicKey, keyIdFor, publicKeyFromDidKey } from './didkey';
export { BODY_VOUCH_OFFICE, type DidWebOptions, didWebDocumentUrl, didWebHost, didWebPath, vouchOfficeOf } from './didweb';
export {
  type JwtHeader,
  type JwtTyp,
  type SignedJwt,
  type VerifiedJwt,
  VC_CONTEXT,
  didKeyOfSecret,
  es256kSign,
  es256kVerify,
  signJwt,
  verifyJwt,
  verifyJwtByKid,
} from './jws';
export { STATUS_LIST_BITS, decodeStatusList, encodeStatusList, statusListBit } from './statuslist';

// ── vocabulary ───────────────────────────────────────────────────────────────

/** The kinds of body the registry knows. The code treats them all the same. */
export const BODY_KINDS = ['school', 'club', 'scouts', 'faith', 'sport', 'employer', 'professional', 'other'] as const;
export type BodyKind = (typeof BODY_KINDS)[number];

/**
 * What a body may vouch, each a boolean `credentialSubject` term.
 *
 * - `member`: belongs to, or is enrolled in, the body.
 * - `guardian_of_member`: an adult the body knows as guardian of one of its members.
 * - `age_over_13`, `age_over_16`, `age_over_18`: worked out by the body from its records.
 * - `helper`: an adult the body vouches for to work with children.
 */
export const BODY_CLAIMS = [
  'member',
  'guardian_of_member',
  'age_over_13',
  'age_over_16',
  'age_over_18',
  'helper',
] as const;
export type BodyClaim = (typeof BODY_CLAIMS)[number];

/** The delegation purpose a body's anchor grants its signing node. */
export const BODY_VOUCH_PURPOSE = 'body.vouch';

/** The JSON-LD context term for this vocabulary. */
export const BODIES_CONTEXT = 'urn:plexus:gip:bodies:v1';

export const REGISTRY_ENTRY_TYPE = 'BodyRegistryEntryCredential';
export const BODY_VOUCH_TYPE = 'BodyVouchCredential';
export const STATUS_LIST_TYPE = 'BitstringStatusListCredential';
export const DELEGATION_EVIDENCE_TYPE = 'SigningNodeDelegation';

/** How far a presentation's `iat` may be from the verifier's clock, in seconds. */
export const PRESENTATION_MAX_SKEW = 300;

/** Plexus kdf-v1 domain flag for a relationship key (EDGE_CREATION). */
export const EDGE_CREATION = 1;

const isKind = (x: unknown): x is BodyKind => (BODY_KINDS as readonly unknown[]).includes(x);
const isClaim = (x: unknown): x is BodyClaim => (BODY_CLAIMS as readonly unknown[]).includes(x);

/** A did:web: a host name, an optional port, an optional path. */
const DID_WEB = /^did:web:[a-z0-9-]+(\.[a-z0-9-]+)+(%3[aA][0-9]+)?(:[A-Za-z0-9._~-]+)*$/;

// ── time ─────────────────────────────────────────────────────────────────────

/** Unix seconds, or RFC 3339 UTC to the second (`2026-12-31T23:59:59Z`). */
export type Instant = number | string;

/** RFC 3339 UTC to the second, `Z` suffix: the only time format credentials carry. */
export const isoSeconds = (unixSeconds: number): string =>
  new Date(unixSeconds * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');

export function parseIsoSeconds(s: unknown): number | null {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(s)) return null;
  const ms = Date.parse(s);
  return Number.isNaN(ms) || isoSeconds(ms / 1000) !== s ? null : ms / 1000;
}

function iso(t: Instant, what: string): string {
  const s = typeof t === 'number' && Number.isSafeInteger(t) ? isoSeconds(t) : t;
  if (parseIsoSeconds(s) === null) throw new WireError('bad_time', `${what}: unix seconds or RFC 3339 UTC to the second`);
  return s as string;
}

// ── keys ─────────────────────────────────────────────────────────────────────

/** The did:key of a public key (a PublicKey or compressed hex). */
export function didKeyOf(pub: PublicKey | string): string {
  return didKeyFromPublicKey(fromHex(typeof pub === 'string' ? pub : pub.toString()));
}

function isPublicKeyHex(s: unknown): s is string {
  if (typeof s !== 'string' || !/^0[23][0-9a-f]{64}$/.test(s)) return false;
  try {
    publicKeyFromDidKey(didKeyOf(s));
    return true;
  } catch {
    return false;
  }
}

/**
 * The holder's key for one relationship, so each relying party sees a
 * different subject and two of them cannot match a holder by key.
 *
 * Derived exactly as Plexus kdf-v1 derives a child: self-ECDH on the root with
 * the invoice `relationship-<first 16 hex of sha256(relyingPartyId)>:1:0`
 * (resource id, EDGE_CREATION domain, child index 0).
 */
export function relationshipKey(holderRootSk: PrivateKey, relyingPartyId: string): PrivateKey {
  if (relyingPartyId.length === 0) throw new WireError('bad_relying_party', 'empty id');
  const tag = createHash('sha256').update(relyingPartyId, 'utf8').digest('hex').slice(0, 16);
  return holderRootSk.deriveChild(holderRootSk.toPublicKey(), `relationship-${tag}:${EDGE_CREATION}:0`);
}

// ── delegation evidence ──────────────────────────────────────────────────────

function isAssociation(x: unknown): x is Association {
  if (typeof x !== 'object' || x === null) return false;
  const o = x as Record<string, unknown>;
  return ['kind', 'display', 'vouchedBy', 'signature'].every((k) => typeof o[k] === 'string');
}

type CheckedDelegation = { ok: true; anchor: string; node: string } | { ok: false; fault: string };

/** Who delegated which node, if the delegation lets that node vouch; else why not. */
function checkDelegation(d: unknown): CheckedDelegation {
  if (!isAssociation(d)) return { ok: false, fault: 'delegation is malformed' };
  const info = readDelegation(d);
  if (info === null) return { ok: false, fault: 'delegation does not verify' };
  if (info.purpose !== BODY_VOUCH_PURPOSE) return { ok: false, fault: `delegation purpose is not ${BODY_VOUCH_PURPOSE}` };
  return { ok: true, anchor: info.anchor, node: info.node };
}

const evidenceOf = (ds: readonly Association[]) =>
  ds.map((d) => ({
    type: DELEGATION_EVIDENCE_TYPE,
    delegation: { kind: d.kind, display: d.display, vouchedBy: d.vouchedBy, signature: d.signature },
  }));

/**
 * The nodes, as compressed hex, that a list's evidence shows `anchor`
 * delegated for body.vouch. Anything else in the evidence is passed over.
 */
function delegatedNodes(evidence: unknown, anchor: string): Set<string> {
  const nodes = new Set<string>();
  if (!Array.isArray(evidence)) return nodes;
  for (const e of evidence) {
    if (e?.type !== DELEGATION_EVIDENCE_TYPE) continue;
    const d = checkDelegation(e.delegation);
    if (d.ok && d.anchor === anchor) nodes.add(d.node);
  }
  return nodes;
}

const nodeHexOf = (did: string): string => hex(publicKeyFromDidKey(did));

// ── registry: who counts ─────────────────────────────────────────────────────

export interface RegistryEntryInput {
  /** The body's did:web. */
  did: string;
  /** The body's root public key, compressed hex: its Plexus page-0. */
  anchor: string;
  kind: BodyKind;
  /** The claims it may vouch. */
  claims: readonly BodyClaim[];
  /** The only times its credentials may expire, such as the end of each school year. Never a birthday. */
  periodEnds: readonly Instant[];
  /** URL of its withdrawal list. */
  statusList: string;
  validFrom: Instant;
  validUntil: Instant;
}

/** A registry entry whose steward's signature checks. Times are RFC 3339. */
export interface RegistryEntry {
  did: string;
  anchor: string;
  kind: BodyKind;
  claims: readonly BodyClaim[];
  periodEnds: readonly string[];
  statusList: string;
  validFrom: string;
  validUntil: string;
  /** The did:key of the steward who signed it. */
  steward: string;
}

/** Why a registry entry's subject is unusable, or null if it is fine. */
function entryFault(cs: any): string | null {
  if (typeof cs !== 'object' || cs === null || Array.isArray(cs)) return 'not an object';
  if (typeof cs.id !== 'string' || !DID_WEB.test(cs.id)) return 'did must be a did:web';
  if (!isPublicKeyHex(cs.anchor)) return 'anchor must be a compressed public key in lowercase hex';
  if (!isKind(cs.kind)) return `kind must be one of ${BODY_KINDS.join(', ')}`;
  if (
    !Array.isArray(cs.claims) ||
    cs.claims.length === 0 ||
    !cs.claims.every(isClaim) ||
    new Set(cs.claims).size !== cs.claims.length
  ) {
    return 'claims must be distinct terms from BODY_CLAIMS';
  }
  if (!Array.isArray(cs.periodEnds) || cs.periodEnds.length === 0 || cs.periodEnds.some((p: unknown) => parseIsoSeconds(p) === null)) {
    return 'periodEnds must be RFC 3339 UTC times';
  }
  if (typeof cs.statusList !== 'string' || !URL.canParse(cs.statusList)) return 'statusList must be a URL';
  return null;
}

/**
 * A registry steward lists a body: its did:web, its anchor, its kind, what it
 * may vouch, when its credentials may expire, and where its withdrawal list
 * lives. A steward may not register itself.
 */
export function issueRegistryEntry(stewardSk: PrivateKey, entry: RegistryEntryInput): string {
  const subject = {
    id: entry.did,
    anchor: entry.anchor,
    kind: entry.kind,
    claims: [...entry.claims],
    periodEnds: entry.periodEnds.map((p, i) => iso(p, `periodEnds[${i}]`)),
    statusList: entry.statusList,
  };
  const fault = entryFault(subject);
  if (fault !== null) throw new WireError('bad_entry', fault);
  if (stewardSk.toPublicKey().toString() === entry.anchor) {
    throw new WireError('self_registration', 'a steward may not register itself');
  }
  const validFrom = iso(entry.validFrom, 'validFrom');
  const validUntil = iso(entry.validUntil, 'validUntil');
  if (parseIsoSeconds(validUntil)! <= parseIsoSeconds(validFrom)!) throw new WireError('bad_time', 'validUntil is not after validFrom');
  return signJwt(
    {
      '@context': [VC_CONTEXT, BODIES_CONTEXT],
      type: ['VerifiableCredential', REGISTRY_ENTRY_TYPE],
      issuer: didKeyOfSecret(stewardSk),
      validFrom,
      validUntil,
      credentialSubject: subject,
    },
    stewardSk,
  );
}

/**
 * Parse a registry entry and check its steward's signature. Null if it is
 * malformed, does not verify, or the steward is the body's own anchor.
 *
 * Whether the steward is trusted, and whether the entry is in date, is the
 * verifier's decision; {@link verifyPresentation} makes both.
 */
export function readRegistryEntry(jwt: string): RegistryEntry | null {
  const v = verifyJwt(jwt);
  if (v === null || v.payload.type[1] !== REGISTRY_ENTRY_TYPE) return null;
  const p = v.payload;
  if (parseIsoSeconds(p.validFrom) === null || parseIsoSeconds(p.validUntil) === null) return null;
  const cs = p.credentialSubject;
  if (entryFault(cs) !== null) return null;
  if (didKeyOf(cs.anchor) === p.issuer) return null; // a body vouching for itself counts for nothing
  return {
    did: cs.id,
    anchor: cs.anchor,
    kind: cs.kind,
    claims: [...cs.claims],
    periodEnds: [...cs.periodEnds],
    statusList: cs.statusList,
    validFrom: p.validFrom,
    validUntil: p.validUntil,
    steward: p.issuer,
  };
}

// ── issuing ──────────────────────────────────────────────────────────────────

export interface VouchInput {
  /** The body's signing node. Its delegation travels on the list, not here. */
  nodeSk: PrivateKey;
  /** The body's registry entry, as {@link readRegistryEntry} returns it. */
  entry: Pick<RegistryEntry, 'did' | 'claims' | 'periodEnds' | 'statusList'>;
  /** The holder's did:key for this relationship. */
  subject: string;
  claim: BodyClaim;
  /** The holder's bit in the body's withdrawal list. */
  statusIndex: number;
  validFrom: Instant;
  /** Must be one of the entry's period ends. */
  validUntil: Instant;
}

/**
 * The body's node vouches one claim about a holder's pairwise key.
 *
 * The credential carries the subject key, the one claim, the dates and a
 * pointer into the withdrawal list. There is no field for a name, a birthdate
 * or a record number, so none can leak. Nor is there one for the node's
 * delegation: the gate finds that on the list, and only while the body
 * honours the node.
 */
export function issueVouch(v: VouchInput): string {
  if (!isClaim(v.claim)) throw new WireError('unknown_claim', String(v.claim));
  if (!v.entry.claims.includes(v.claim)) throw new WireError('claim_not_allowed', `${v.entry.did} may not vouch ${v.claim}`);
  const validFrom = iso(v.validFrom, 'validFrom');
  const validUntil = iso(v.validUntil, 'validUntil');
  if (!v.entry.periodEnds.includes(validUntil)) {
    throw new WireError('not_a_period_end', `validUntil ${validUntil} is not one of the body's published period ends`);
  }
  if (parseIsoSeconds(validUntil)! <= parseIsoSeconds(validFrom)!) throw new WireError('bad_time', 'validUntil is not after validFrom');
  try {
    publicKeyFromDidKey(v.subject);
  } catch {
    throw new WireError('bad_subject', 'subject must be a secp256k1 did:key');
  }
  if (!Number.isInteger(v.statusIndex) || v.statusIndex < 0 || v.statusIndex >= STATUS_LIST_BITS) {
    throw new WireError('bad_status_index', String(v.statusIndex));
  }
  return signJwt(
    {
      '@context': [VC_CONTEXT, BODIES_CONTEXT],
      type: ['VerifiableCredential', BODY_VOUCH_TYPE],
      issuer: v.entry.did,
      validFrom,
      validUntil,
      credentialSubject: { id: v.subject, [v.claim]: true },
      credentialStatus: {
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: String(v.statusIndex),
        statusListCredential: v.entry.statusList,
      },
    },
    v.nodeSk,
  );
}

export interface StatusListInput {
  /** The body's did:web: the same issuer as its credentials. */
  issuer: string;
  /**
   * The anchor's delegation of every node the body still honours, for
   * {@link BODY_VOUCH_PURPOSE}: the signing node's, and an old node's while its
   * vouches are still to pass. A node left out is withdrawn.
   */
  delegations: readonly Association[];
  /** Where the list is published: the registry entry's `statusList`. */
  url: string;
  /** Withdrawn indexes. */
  revoked: number[];
  validFrom: Instant;
}

/**
 * The body's withdrawal list, signed by one of its nodes and carrying, as
 * evidence, the delegation of every node the body honours.
 */
export function issueStatusList(nodeSk: PrivateKey, c: StatusListInput): string {
  if (!DID_WEB.test(c.issuer)) throw new WireError('bad_issuer', 'issuer must be the body did:web');
  const nodes = new Set<string>();
  const anchors = new Set<string>();
  c.delegations.forEach((x, i) => {
    const d = checkDelegation(x);
    if (!d.ok) throw new WireError('bad_delegation', `delegations[${i}]: ${d.fault}`);
    if (nodes.has(d.node)) throw new WireError('bad_delegation', `delegations[${i}]: one delegation per node`);
    nodes.add(d.node);
    anchors.add(d.anchor);
  });
  if (anchors.size > 1) throw new WireError('bad_delegation', 'the delegations must all be from one anchor');
  if (!nodes.has(nodeSk.toPublicKey().toString())) {
    throw new WireError('bad_delegation', 'the signing node must be among the delegations');
  }
  return signJwt(
    {
      '@context': [VC_CONTEXT],
      type: ['VerifiableCredential', STATUS_LIST_TYPE],
      id: c.url,
      issuer: c.issuer,
      validFrom: iso(c.validFrom, 'validFrom'),
      credentialSubject: {
        id: `${c.url}#list`,
        type: 'BitstringStatusList',
        statusPurpose: 'revocation',
        encodedList: encodeStatusList(c.revoked),
      },
      evidence: evidenceOf(c.delegations),
    },
    nodeSk,
  );
}

// ── presenting ───────────────────────────────────────────────────────────────

export interface PresentInput {
  credentialJwt: string;
  /** The holder's relationship key: the credential's subject. */
  subjectSk: PrivateKey;
  /** The relying party the presentation is for. */
  audience: string;
  /** The relying party's one-time challenge. */
  nonce: string;
  /** Unix seconds. */
  at: number;
}

/** The holder answers a challenge: their key signs the credential, the audience and the nonce. */
export function present(p: PresentInput): string {
  if (!Number.isSafeInteger(p.at)) throw new WireError('bad_time', 'at: whole unix seconds');
  return signJwt({ vp: p.credentialJwt, aud: p.audience, nonce: p.nonce, iat: p.at }, p.subjectSk, 'vp+jwt');
}

// ── verifying ────────────────────────────────────────────────────────────────

/** Every refusal, in the order the checks run. The first that fails is the reason given. */
export const BODY_REFUSALS = [
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
] as const;
export type BodyRefusal = (typeof BODY_REFUSALS)[number];

export interface VerifyPresentationOptions {
  /** This relying party's id. */
  audience: string;
  /** The challenge it sent. */
  nonce: string;
  /** did:keys of the registry stewards it trusts. */
  stewards: ReadonlySet<string>;
  /** Registry entry JWTs it holds. */
  registryEntries: readonly string[];
  /** Withdrawal list JWTs it holds, by URL. */
  statusLists: Readonly<Record<string, string>>;
  /** Unix seconds. */
  now: number;
  /** The claim it needs. */
  require: BodyClaim;
}

export type BodyVerdict =
  | { ok: true; body: { did: string; kind: BodyKind }; claim: BodyClaim; subject: string }
  | { ok: false; reason: BodyRefusal };

type Fail = { ok: false; reason: BodyRefusal };
const fail = (reason: BodyRefusal): Fail => ({ ok: false, reason });

interface Vouch {
  issuer: string;
  /** The node's did:key, from the JWT header. */
  node: string;
  subject: string;
  claim: BodyClaim;
  terms: Record<string, unknown>;
  validFrom: number;
  validUntil: number;
  validUntilIso: string;
  statusUrl: string;
  statusIndex: number;
}

/** A vouch the rules can use, or null. */
function toVouch(v: SignedJwt | null): Vouch | null {
  if (v === null || v.payload.type[1] !== BODY_VOUCH_TYPE) return null;
  const p = v.payload;
  // One format: the delegation is on the list, so a vouch carrying evidence is not one.
  if (Object.hasOwn(p, 'evidence')) return null;
  if (!DID_WEB.test(p.issuer)) return null;
  const validFrom = parseIsoSeconds(p.validFrom);
  const validUntil = parseIsoSeconds(p.validUntil);
  if (validFrom === null || validUntil === null) return null;
  const s = p.credentialStatus;
  if (s?.type !== 'BitstringStatusListEntry' || s.statusPurpose !== 'revocation') return null;
  if (typeof s.statusListIndex !== 'string' || !/^(0|[1-9][0-9]{0,9})$/.test(s.statusListIndex)) return null;
  if (typeof s.statusListCredential !== 'string') return null;
  const cs = p.credentialSubject;
  if (typeof cs !== 'object' || cs === null || Array.isArray(cs) || typeof cs.id !== 'string') return null;
  try {
    publicKeyFromDidKey(cs.id);
  } catch {
    return null;
  }
  // Exactly one claim, and nothing else: a credential with a name in it does not verify.
  const terms = Object.keys(cs).filter((k) => k !== 'id');
  const claim = terms[0];
  if (terms.length !== 1 || !isClaim(claim) || cs[claim] !== true) return null;
  return {
    issuer: p.issuer,
    node: v.signer,
    subject: cs.id,
    claim,
    terms: cs,
    validFrom,
    validUntil,
    validUntilIso: p.validUntil,
    statusUrl: s.statusListCredential,
    statusIndex: Number(s.statusListIndex),
  };
}

interface HeldList {
  bits: Uint8Array;
  /** The nodes, as compressed hex, its evidence shows the entry's anchor delegated. */
  nodes: Set<string>;
}

/**
 * The entry's withdrawal list as the verifier holds it, or null unless it is
 * well formed, in force, and signed by a node its own evidence shows the
 * entry's anchor delegated for body.vouch.
 */
function heldList(jwt: string | undefined, entry: RegistryEntry, now: number): HeldList | null {
  if (jwt === undefined) return null;
  const v = verifyJwtByKid(jwt);
  if (v === null || v.payload.type[1] !== STATUS_LIST_TYPE) return null;
  const p = v.payload;
  if (p.issuer !== entry.did || p.id !== entry.statusList) return null;
  const validFrom = parseIsoSeconds(p.validFrom);
  if (validFrom === null || validFrom > now) return null;
  const cs = p.credentialSubject;
  if (cs?.type !== 'BitstringStatusList' || cs.statusPurpose !== 'revocation' || typeof cs.encodedList !== 'string') return null;
  const nodes = delegatedNodes(p.evidence, entry.anchor);
  if (!nodes.has(nodeHexOf(v.signer))) return null;
  try {
    return { bits: decodeStatusList(cs.encodedList), nodes };
  } catch {
    return null;
  }
}

function inForce(e: RegistryEntry, now: number): boolean {
  return parseIsoSeconds(e.validFrom)! <= now && now < parseIsoSeconds(e.validUntil)!;
}

function checkAgainst(entry: RegistryEntry, vouch: Vouch, o: VerifyPresentationOptions): BodyVerdict {
  if (vouch.statusUrl !== entry.statusList || !Object.hasOwn(o.statusLists, entry.statusList)) return fail('no_status_list');
  const list = heldList(o.statusLists[entry.statusList], entry, o.now);
  if (list === null || vouch.statusIndex >= list.bits.length * 8) return fail('no_status_list');
  // The vouch's node must be on the same list: a node the body withdrew is not.
  if (!list.nodes.has(nodeHexOf(vouch.node))) return fail('node_not_delegated');
  // The registry also fixes when credentials may expire, so an expiry that is a birthday does not pass.
  if (!entry.claims.includes(vouch.claim) || !entry.periodEnds.includes(vouch.validUntilIso)) return fail('claim_not_allowed');
  if (o.now < vouch.validFrom) return fail('not_yet_valid');
  if (o.now >= vouch.validUntil) return fail('expired');
  if (statusListBit(list.bits, vouch.statusIndex)) return fail('withdrawn');
  if (vouch.terms[o.require] !== true) return fail('missing_claim');
  return { ok: true, body: { did: entry.did, kind: entry.kind }, claim: o.require, subject: vouch.subject };
}

/**
 * The relying party's gate. Offline: it uses only what it holds, and never
 * contacts the body. The checks run in the order of {@link BODY_REFUSALS} and
 * the first that fails is the reason given.
 */
export function verifyPresentation(presentationJwt: string, o: VerifyPresentationOptions): BodyVerdict {
  const vp = verifyJwtByKid(presentationJwt, 'vp+jwt');
  const pp = vp?.payload;
  if (
    vp === null ||
    typeof pp?.vp !== 'string' ||
    typeof pp.aud !== 'string' ||
    typeof pp.nonce !== 'string' ||
    !Number.isSafeInteger(pp.iat)
  ) {
    return fail('bad_presentation');
  }
  if (pp.aud !== o.audience) return fail('wrong_audience');
  if (pp.nonce !== o.nonce) return fail('wrong_nonce');
  if (Math.abs(o.now - pp.iat) > PRESENTATION_MAX_SKEW) return fail('stale');

  const vouch = toVouch(verifyJwtByKid(pp.vp));
  if (vouch === null) return fail('bad_credential');
  if (vp.signer !== vouch.subject) return fail('subject_mismatch');

  const entries = o.registryEntries
    .map((jwt) => readRegistryEntry(jwt))
    .filter((e): e is RegistryEntry => e !== null && o.stewards.has(e.steward) && e.did === vouch.issuer && inForce(e, o.now));
  if (entries.length === 0) return fail('not_registered');

  // More than one live entry (a renewal, say): the first that accepts wins, else the first reason.
  let first: BodyVerdict | null = null;
  for (const entry of entries) {
    const r = checkAgainst(entry, vouch, o);
    if (r.ok) return r;
    first ??= r;
  }
  return first!;
}
