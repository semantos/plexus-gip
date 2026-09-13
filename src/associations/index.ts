/**
 * Identity ASSOCIATIONS — things mapped against a cert, not the cert itself.
 *
 * The first cut of the cert store made a LinkedIn name *be* the identity: one
 * provider, all or nothing, and the store simply asserted it. That is wrong in
 * both directions. A person is not their LinkedIn account, and a verifier
 * asking "who is this" should not be handed everything we know in order to
 * learn one thing.
 *
 * So a cert commits to a SET of associations — a LinkedIn account, a
 * professional body membership number, an ORCID, an employer, a licence number
 * — as a merkle root over `core/protocol-types/src/field-tree` (L8). The holder
 * discloses whichever ones they choose, each with a proof, and the overlay
 * DECODES the association only if the proof walks to the committed root.
 *
 * ## The holder assembles their own set, and that forces the signature
 *
 * Decided 2026-08-13: the holder builds the set LOCALLY, so no certifier ever
 * sees the associations they did not disclose. The certifier is a witness to a
 * root, not a custodian of a profile.
 *
 * That decision breaks a naive `vouchedBy: string`. If nobody but the holder
 * sees the values, `vouchedBy` is a field the holder types — they could write a
 * professional body's key beside a membership number they invented, and the
 * merkle proof would verify, because it proves membership in THEIR OWN set.
 *
 * So each association carries the voucher's SIGNATURE, and it covers the
 * SUBJECT KEY. Without the subject in the preimage a signed association is a
 * bearer token: copy someone else's signed LinkedIn leaf into your own set and
 * it still verifies.
 *
 * ## Two independent facts, both required
 *
 * ⚠️ A verified disclosure now establishes exactly two things, and they are not
 * the same thing:
 *
 *   1. **Membership** — the merkle proof. This association was committed under
 *      this root before anyone asked, so it was not composed to suit a
 *      question and the set cannot be quietly edited.
 *   2. **Attestation** — the voucher's signature over (subject, kind, display).
 *      Whoever `vouchedBy` names actually said this, about this subject.
 *
 * Neither implies the other, and neither makes the association TRUE — a voucher
 * can be wrong or lying. What they rule out is the holder inventing it. A
 * self-asserted association needs no special case: the subject signs it
 * themselves, `vouchedBy` is their own key, and the page shows it as such.
 *
 * ## What it leaks
 *
 * ⚠️ **The leaf count.** A merkle proof's sibling path reveals roughly how many
 * associations exist, even when one is disclosed. Not a defect to fix here —
 * hiding it needs padding to a fixed width, which is a schema decision — but a
 * property to know before telling anyone this discloses nothing else.
 *
 * The undisclosed values themselves are safe: a verifier sees sibling HASHES.
 */

import { createHash } from 'node:crypto';
import { PrivateKey, PublicKey, Signature, Utils } from '@bsv/sdk';
import {
  type FieldDisclosureProof,
  type FieldLeaf,
  type FieldTree,
  buildFieldTree,
  discloseField,
  verifyFieldDisclosure,
} from '../field-tree';

/**
 * Schema fingerprint for v1 associations.
 *
 * Bound into every leaf hash by `computeFieldLeaf`, so a leaf from a different
 * schema cannot be replayed into this one even with an identical label and
 * value.
 */
export const ASSOCIATION_SCHEMA_V1: Uint8Array = new Uint8Array(
  createHash('sha256').update('semantos.identity.associations/v1').digest(),
);

/** Association kinds in use. Not exhaustive — the label is just a string. */
export const ASSOCIATION_KINDS = {
  linkedin: 'social.linkedin',
  /**
   * Control of an account on a further social platform, so that no single
   * provider IS the identity — the value is the BREADTH, not any one leaf. See
   * `../social/providers`, which mints these, and its `humanityEvidence`: a key
   * vouched across several independent platforms is expensive to fake in a way
   * one throwaway account is not. Each still certifies account CONTROL, never a
   * verified human — every provider says exactly that in its own words.
   */
  github: 'social.github',
  google: 'social.google',
  facebook: 'social.facebook',
  x: 'social.x',
  familysearch: 'social.familysearch',
  professionalBody: 'body.membership',
  orcid: 'research.orcid',
  email: 'contact.email',
  licence: 'credential.licence',
  /**
   * A KINSHIP edge to another person — parent, child, sibling, spouse. The leaf
   * of the Genealogical Identity Protocol v2 (`../social/kinship`): `display`
   * carries the relationship and the counterpart's page-0 key, `vouchedBy` is
   * who asserts it. A kinship CLAIM is one such edge; a kinship BOND is the pair
   * (A→B and B→A) both present — the GIP's child→parent→child signing scheme
   * expressed as two vouches rather than a chain of GEDCOM re-signings.
   */
  kinship: 'kin.edge',
  /**
   * An attestation that the subject's biographical RECORD hashes to a value —
   * `display` is that `recordHash` (`../social/record`). A certifier such as
   * FamilySearch signs this to co-vouch a whole record without holding it (see
   * `../social/familysearch`); the hash is opaque here, so this kind couples to
   * no particular record format.
   */
  record: 'kin.record',
  /**
   * An attestation that a computed PREDICATE holds over the subject's lineage —
   * `display` is a canonical predicate string like `gen-depth>=3` or
   * `ancestry-region:scotland-highland>=1` (`../social/predicate`). The L0 rung
   * of the ZK predicate-proof ladder: a certifier that can see the tree signs
   * the property, revealing nothing of the tree itself. See
   * `docs/design/GIP-V2-PREDICATE-PROOFS.md`.
   */
  predicate: 'kin.predicate',
  /**
   * "This key is a machine I am accountable for."
   *
   * `display` is the OPERATOR's certId. Vouched by the operator, and
   * `vouchPreimage` binds the machine's subject key — so it is a signed,
   * checkable statement of accountability rather than a label anyone can apply
   * to anyone.
   *
   * ⚠️ It cannot prove the NEGATIVE. An operator who declines to declare a key
   * they control is indistinguishable from someone who has no machines, so this
   * attributes honest fleets and does not detect dishonest ones. See
   * `docs/design/BOOMSPACE-LABEL-VS-KEY-SWEEP.md`.
   */
  machineOperator: 'machine.operator',
} as const;

export interface Association {
  /** The merkle label, e.g. `social.linkedin`. */
  readonly kind: string;
  /** What a page may show — a name, a membership number, a handle. */
  readonly display: string;
  /**
   * Hex public key of whoever attested THIS association. Per-association
   * because a LinkedIn handle and a licence number are vouched by different
   * parties, and one `certifier` field would erase that.
   */
  readonly vouchedBy: string;
  /**
   * DER-hex ECDSA signature by `vouchedBy` over {@link vouchPreimage}.
   *
   * The whole reason holder-assembled sets are safe. Without it this struct
   * says "the holder claims X vouched"; with it, X did.
   */
  readonly signature: string;
}

const enc = new TextEncoder();
/** Length-prefixed field, matching the claims-preimage idiom. */
const lp = (v: string): string => `${enc.encode(v).length}:${v}`;

/**
 * Canonical bytes for an association's value.
 *
 * `kind` is deliberately absent: `computeFieldLeaf` already binds the label
 * into the leaf hash, so including it here would be redundant, and redundancy
 * in a canonical encoding is somewhere for two implementations to disagree.
 */
export function associationValue(
  a: Pick<Association, 'display' | 'vouchedBy' | 'signature'>,
): Uint8Array {
  return enc.encode(`${lp(a.display)}${lp(a.vouchedBy)}${lp(a.signature)}`);
}

/**
 * What a voucher signs.
 *
 * ⚠️ `subjectPublicKey` is the load-bearing field. Sign only (kind, display)
 * and the result is a bearer token — anyone can paste a real institution's
 * signed leaf into their own association set and have it verify. Binding the
 * subject makes an attestation about one person unusable by another.
 *
 * Domain-separated so a signature over this can never be replayed as a
 * signature over some other semantos preimage.
 */
export function vouchPreimage(
  subjectPublicKey: string,
  kind: string,
  display: string,
): string {
  return `semantos association/v1${lp(subjectPublicKey)}${lp(kind)}${lp(display)}`;
}

/** Sign an association as its voucher. DER hex out. */
export function signAssociation(
  voucherSk: PrivateKey,
  subjectPublicKey: string,
  kind: string,
  display: string,
): string {
  const msg = Array.from(enc.encode(vouchPreimage(subjectPublicKey, kind, display)));
  return Utils.toHex(voucherSk.sign(msg).toDER() as number[]);
}

/** Did `vouchedBy` really attest this association about this subject? */
export function verifyVouch(a: Association, subjectPublicKey: string): boolean {
  try {
    const msg = Array.from(enc.encode(vouchPreimage(subjectPublicKey, a.kind, a.display)));
    return PublicKey.fromString(a.vouchedBy)
      .verify(msg, Signature.fromDER(Utils.toArray(a.signature, 'hex')));
  } catch {
    return false;
  }
}

/**
 * Decode `associationValue` bytes.
 *
 * ⚠️ Walks BYTES, not string indices. `lp()` writes a UTF-8 BYTE length, so a
 * decoder slicing a JavaScript string would be correct for ASCII and wrong for
 * everything else — an em-dash, an accent, any CJK character. That failure is
 * silent (the association simply refuses to decode) and lands hardest on names
 * that are not Anglo, which for an identity system is the worst possible place
 * to be subtly broken. Caught on a live disclosure whose display value
 * contained an em-dash while its ASCII sibling verified fine.
 */
function decodeAssociationValue(
  bytes: Uint8Array,
): Pick<Association, 'display' | 'vouchedBy' | 'signature'> | null {
  const dec = new TextDecoder();
  const COLON = 0x3a;
  const read = (offset: number): { value: string; next: number } | null => {
    let colon = -1;
    for (let i = offset; i < bytes.length; i++) {
      if (bytes[i] === COLON) { colon = i; break; }
    }
    if (colon === -1) return null;
    const len = Number(dec.decode(bytes.subarray(offset, colon)));
    if (!Number.isInteger(len) || len < 0) return null;
    const end = colon + 1 + len;
    if (end > bytes.length) return null;
    return { value: dec.decode(bytes.subarray(colon + 1, end)), next: end };
  };
  const display = read(0);
  if (display === null) return null;
  const vouchedBy = read(display.next);
  if (vouchedBy === null) return null;
  const signature = read(vouchedBy.next);
  // Trailing bytes mean the encoding was not produced by `associationValue`,
  // and a decoder that ignored them would accept two encodings of one value.
  if (signature === null || signature.next !== bytes.length) return null;
  return { display: display.value, vouchedBy: vouchedBy.value, signature: signature.value };
}

const toLeaf = (a: Association): FieldLeaf => ({ label: a.kind, value: associationValue(a) });

/**
 * Commit a set of associations. The root is what a certifier signs.
 *
 * A certifier signing the ROOT rather than the values is the point: they attest
 * that this key committed to this set, while each association keeps its own
 * `vouchedBy`. One signature does not launder every association into being
 * vouched by whoever signed last.
 */
export function buildAssociationSet(
  associations: readonly Association[],
  schemaFingerprint: Uint8Array = ASSOCIATION_SCHEMA_V1,
): FieldTree {
  return buildFieldTree(schemaFingerprint, associations.map(toLeaf));
}

/** Disclose exactly one association. Throws if that kind is not in the set. */
export function discloseAssociation(
  associations: readonly Association[],
  kind: string,
  schemaFingerprint: Uint8Array = ASSOCIATION_SCHEMA_V1,
): FieldDisclosureProof {
  return discloseField(schemaFingerprint, associations.map(toLeaf), kind);
}

/**
 * Verify a disclosure against a trusted root, and decode it.
 *
 * Verification and decoding are ONE call, and that is the design. A pair of
 * functions invites a caller to decode first and check later, or to skip the
 * check on a path where it "obviously" already happened — and a decoded
 * association that was never proven is exactly a database row wearing a
 * cryptographic costume.
 *
 * Returns null on any failure. The caller cannot obtain the value without the
 * proof having walked to `expectedRoot`.
 */
export function readDisclosedAssociation(
  proof: FieldDisclosureProof,
  expectedRoot: Uint8Array,
  subjectPublicKey: string,
): Association | null {
  if (!verifyFieldDisclosure(proof, expectedRoot)) return null;
  const decoded = decodeAssociationValue(proof.value);
  if (decoded === null) return null;
  const assoc: Association = { kind: proof.label, ...decoded };
  // BOTH checks, in one call, for the same reason the merkle check is here:
  // a caller that could obtain the association and verify the vouch later is a
  // caller that will eventually forget to.
  if (!verifyVouch(assoc, subjectPublicKey)) return null;
  return assoc;
}
