/**
 * KINSHIP edges — the Genealogical Identity Protocol v2 leaf.
 *
 * A relationship is not a row in a GEDCOM file; it is a SIGNED EDGE between two
 * page-0 keys. This is the `kin.edge` leaf of the association graph, and it
 * carries the whole of "Proof of Ancestor" without a single Longest-Common-
 * Substring comparison. See `docs/design/GIP-V2-GENEALOGICAL-IDENTITY.md`.
 *
 * ## A claim, and a bond
 *
 * A kinship **claim** is one directed, signed edge — *"in my records, my
 * <relation> is <counterpart>"* — living in the subject's own association set.
 * Its `vouchedBy` may be the subject themselves (self-asserted) or a third
 * party (a relative, or FamilySearch co-signing what it can verify).
 *
 * A kinship **bond** is the pair present in both directions: A's set says B is
 * A's parent, and B's set says A is B's child. **This pair is exactly the 2024
 * GIP's child→parent→child signing scheme** — mutual, each endpoint holding a
 * key — expressed as two `signAssociation` vouches rather than a GEDCOM round
 * trip. A bond is strictly stronger than a claim: a claim is one person's word;
 * a bond is two people who each control their root, agreeing.
 *
 * ## Direction, pinned once so two implementations cannot disagree
 *
 * `display = "<relation>|<counterpart-page0-pubkey>"` reads from the SUBJECT's
 * perspective: *"my <relation> is <counterpart>."* So in A's set `parent|B`
 * means B is A's parent, and in B's set `child|A` means A is B's child — the two
 * halves of one real relationship. A valid bond requires each to name the other
 * as counterpart AND the relations to be inverses (`parent`↔`child`,
 * `sibling`↔`sibling`, `spouse`↔`spouse`).
 *
 * ## Where verification lives
 *
 * Signature + membership verification is `readDisclosedAssociation`'s job (merkle
 * proof to the committed root + the voucher signature bound to the subject key),
 * exactly as for any association. The helpers here operate on ALREADY-VERIFIED
 * edges and check the STRUCTURE — relation vocabulary, inverse consistency,
 * ancestral continuity. Keeping structure and cryptography in separate calls is
 * the same discipline the association substrate already holds: a decoded edge
 * that was never proven is a database row in a cryptographic costume.
 */

import { PrivateKey, PublicKey } from '@bsv/sdk';
import { ASSOCIATION_KINDS, type Association, signAssociation } from '../associations';

/**
 * The atomic kinship relations, from the SUBJECT's perspective.
 *
 * Only the atoms: a grandparent is a *path* of two `parent` hops, not a
 * relation, and modelling it as one would invent a second encoding for the same
 * fact. Qualified kinship (step-, adoptive-, co-) is a documented extension —
 * add the token here with its inverse in {@link KIN_INVERSE}; the GIP's emphasis
 * on non-traditional families is met by widening this vocabulary, not by
 * special-casing the edge.
 */
export const KIN_RELATIONS = {
  parent: 'parent',
  child: 'child',
  sibling: 'sibling',
  spouse: 'spouse',
} as const;

export type KinRelation = (typeof KIN_RELATIONS)[keyof typeof KIN_RELATIONS];

/**
 * The inverse of each relation — what the OTHER endpoint must assert for a bond.
 *
 * `parent`↔`child` are asymmetric; `sibling` and `spouse` are their own
 * inverses. A bond is consistent only when B's relation equals the inverse of
 * A's, so this table is the whole of bond validation's semantics.
 */
export const KIN_INVERSE: Readonly<Record<KinRelation, KinRelation>> = {
  parent: 'child',
  child: 'parent',
  sibling: 'sibling',
  spouse: 'spouse',
} as const;

function isKinRelation(s: string): s is KinRelation {
  return Object.prototype.hasOwnProperty.call(KIN_INVERSE, s);
}

/** Canonical compressed hex for a public key, or null if it is not one. */
function normalizePubkey(hex: string): string | null {
  try {
    return PublicKey.fromString(hex).toString();
  } catch {
    return null;
  }
}

/**
 * Encode an edge's `display`. Throws on a bad relation or counterpart key —
 * minting a malformed edge should fail loudly at construction, not decode to
 * null later where the cause is lost.
 */
export function encodeKinDisplay(relation: KinRelation, counterpartPubkey: string): string {
  if (!isKinRelation(relation)) throw new Error(`unknown kin relation: ${relation}`);
  const pub = normalizePubkey(counterpartPubkey);
  if (pub === null) throw new Error('counterpart is not a valid public key');
  // A relation token is lowercase letters and a compressed pubkey is hex; neither
  // contains "|", so a single separator is unambiguous.
  return `${relation}|${pub}`;
}

export interface KinEdge {
  readonly relation: KinRelation;
  /** The counterpart's page-0 pubkey, canonical compressed hex. */
  readonly counterpart: string;
}

/**
 * Parse and VALIDATE an edge's `display`. Returns null unless it is exactly
 * `<known-relation>|<valid-pubkey>` with no trailing junk — an unknown relation
 * has no defined inverse and so cannot take part in a bond, and is refused here
 * rather than surfacing later as an unverifiable half.
 */
export function parseKinDisplay(display: string): KinEdge | null {
  const bar = display.indexOf('|');
  if (bar === -1) return null;
  if (display.indexOf('|', bar + 1) !== -1) return null; // exactly one separator
  const relation = display.slice(0, bar);
  if (!isKinRelation(relation)) return null;
  const counterpart = normalizePubkey(display.slice(bar + 1));
  if (counterpart === null) return null;
  return { relation, counterpart };
}

/** Is this association a kinship edge with a well-formed display? */
export function isKinEdge(a: Pick<Association, 'kind' | 'display'>): boolean {
  return a.kind === ASSOCIATION_KINDS.kinship && parseKinDisplay(a.display) !== null;
}

/** The parsed edge if `a` is a valid kin.edge, else null. */
export function readKinEdge(a: Pick<Association, 'kind' | 'display'>): KinEdge | null {
  if (a.kind !== ASSOCIATION_KINDS.kinship) return null;
  return parseKinDisplay(a.display);
}

/**
 * A kinship claim, signed by `voucherSk`, about `subjectPage0`.
 *
 * The general form: the voucher attests *"subject's <relation> is counterpart."*
 * For a self-asserted claim the voucher's key IS the subject; for a third-party
 * attestation (a relative, or FamilySearch) it is not. The subject key is bound
 * into the signature by `signAssociation`, so the edge cannot be lifted into
 * anyone else's set.
 */
export function kinClaim(
  voucherSk: PrivateKey,
  subjectPage0: string,
  relation: KinRelation,
  counterpartPage0: string,
): Association {
  const kind = ASSOCIATION_KINDS.kinship;
  const display = encodeKinDisplay(relation, counterpartPage0);
  return {
    kind,
    display,
    vouchedBy: voucherSk.toPublicKey().toString(),
    signature: signAssociation(voucherSk, subjectPage0, kind, display),
  };
}

/**
 * A self-asserted kinship claim — the common case. The subject signs their own
 * edge, so `vouchedBy` is their page-0 and a reader weighs it as a self-claim.
 */
export function selfKinClaim(
  egoSk: PrivateKey,
  relation: KinRelation,
  counterpartPage0: string,
): Association {
  return kinClaim(egoSk, egoSk.toPublicKey().toString(), relation, counterpartPage0);
}

/**
 * Do two verified edges form a consistent BOND?
 *
 * `edgeA` lives in A's set (subject `egoA`); `edgeB` in B's set (subject `egoB`).
 * A bond holds iff A names B as counterpart, B names A, and B's relation is the
 * inverse of A's. Structure only — each edge's signature and membership are the
 * caller's to establish with `readDisclosedAssociation` before calling this.
 */
export function kinBondConsistent(
  edgeA: Pick<Association, 'kind' | 'display'>,
  egoA: string,
  edgeB: Pick<Association, 'kind' | 'display'>,
  egoB: string,
): boolean {
  const a = readKinEdge(edgeA);
  const b = readKinEdge(edgeB);
  if (a === null || b === null) return false;
  const na = normalizePubkey(egoA);
  const nb = normalizePubkey(egoB);
  if (na === null || nb === null) return false;
  // Each must point at the other, and the relations must be inverses.
  return a.counterpart === nb && b.counterpart === na && b.relation === KIN_INVERSE[a.relation];
}

/** One hop of an ancestor path: an edge in `egoPub`'s set naming their parent. */
export interface AncestorHop {
  readonly egoPub: string;
  readonly edge: Pick<Association, 'kind' | 'display'>;
}

/**
 * Verify an ancestor PATH is cryptographically continuous — the v2 replacement
 * for "longest unbroken chain of ancestors."
 *
 * Each hop must be a `parent` edge in that hop's ego set, and the parent it
 * names must be the NEXT hop's ego. That chaining — counterpart(i) == ego(i+1) —
 * is what "unbroken" now means: continuous by key, not similar by text. The
 * terminal ancestor is `counterpart` of the last hop.
 *
 * Structure only: verify each hop's edge against its ego's committed root with
 * `readDisclosedAssociation` first. An empty path proves no ancestry and returns
 * false.
 */
export function verifyAncestorPath(hops: readonly AncestorHop[]): boolean {
  if (hops.length === 0) return false;
  const parsed: KinEdge[] = [];
  for (const hop of hops) {
    const e = readKinEdge(hop.edge);
    if (e === null || e.relation !== KIN_RELATIONS.parent) return false;
    if (normalizePubkey(hop.egoPub) === null) return false;
    parsed.push(e);
  }
  for (let i = 0; i < hops.length - 1; i++) {
    // The parent named at hop i must be the ego whose edge is hop i+1.
    if (parsed[i]!.counterpart !== normalizePubkey(hops[i + 1]!.egoPub)) return false;
  }
  return true;
}
