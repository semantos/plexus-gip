/**
 * FamilySearch (and any certifier) as an ATTESTOR — not a custodian.
 *
 * The whole proposition of GIP v2 for an institution like FamilySearch: lend
 * your authority to people's self-sovereign identities without holding their
 * keys, custodying their accounts, or taking on KYC/recovery liability. It does
 * that by CO-SIGNING facts it can verify — nothing more. See
 * `docs/design/GIP-V2-GENEALOGICAL-IDENTITY.md` §7.
 *
 * Two things a certifier can sign, both bound to the subject's key so neither is
 * a bearer token:
 *
 *   1. **A kinship edge** — a third-party `kin.edge` vouch: "this parent→child
 *      link matches an authoritative record." Just `kinClaim` with the
 *      certifier's key (`familySearchKinVouch`).
 *   2. **A whole record** — `recordAttestation` over the record's `recordHash`
 *      (from `../social/record`). The hash is passed in OPAQUE, so this module
 *      never imports the record codec: a certifier attests a digest, and how
 *      that digest was computed is the codec's concern, not this one.
 *
 * ## Off-server signing is unchanged
 *
 * These constructors are pure crypto; the certifier's private key never has to
 * reach a server. FamilySearch loads its key wherever it lives (the boomspace
 * certifier already does exactly this — `cartridges/boomspace/certify.ts`
 * `loadCertifier`) and calls these. The substrate's job is the attestation shape
 * and its verification, which is what a relying party needs and what `certify.ts`
 * did not have.
 *
 * ## Trust is the verifier's, and it is explicit
 *
 * A signature proves who signed; it does not make the claim true, and it does
 * not say whether the signer is worth believing. {@link vouchTier} makes that
 * judgment explicit and local: the verifier supplies the certifier keys it
 * trusts, and an edge is weighed `certifier` / `self` / `peer` accordingly.
 * Per-edge provenance is preserved throughout — a FamilySearch vouch never
 * launders a self-claim, and a self-claim is never dressed up as a certifier's.
 */

import type { PrivateKey } from '@bsv/sdk';
import {
  ASSOCIATION_KINDS,
  type Association,
  signAssociation,
  verifyVouch,
} from '../associations';
import { type KinRelation, kinClaim } from './kinship';

/** A certifier identity a verifier may choose to trust. FamilySearch is the motivating one. */
export interface Certifier {
  readonly name: string;
  /** The certifier's public key, hex. */
  readonly pubkey: string;
}

/** The association kind a record attestation carries. */
export const RECORD_ATTESTATION_KIND: string = ASSOCIATION_KINDS.record;

/** A 32-byte hex digest — the shape `recordHash` produces. */
const HASH_RE = /^[0-9a-f]{64}$/i;

/**
 * A certifier's attestation that `subjectPage0`'s record hashes to `recordHash`.
 *
 * Bound to the subject key by `signAssociation`, so it cannot be replayed about
 * anyone else. Throws on a malformed hash — attesting a digest of the wrong
 * shape is a bug to surface at construction, not to discover on a failed verify.
 */
export function recordAttestation(
  voucherSk: PrivateKey,
  subjectPage0: string,
  recordHash: string,
): Association {
  if (!HASH_RE.test(recordHash)) throw new Error('recordHash must be 32-byte hex');
  const kind = RECORD_ATTESTATION_KIND;
  const display = recordHash.toLowerCase();
  return {
    kind,
    display,
    vouchedBy: voucherSk.toPublicKey().toString(),
    signature: signAssociation(voucherSk, subjectPage0, kind, display),
  };
}

/** The attested record hash if `a` is a well-formed record attestation, else null. */
export function readRecordAttestation(a: Pick<Association, 'kind' | 'display'>): string | null {
  if (a.kind !== RECORD_ATTESTATION_KIND) return null;
  return HASH_RE.test(a.display) ? a.display.toLowerCase() : null;
}

/**
 * Does this attestation bind `subjectPage0` to `expectedHash`, signed by its
 * voucher? Checks the hash AND the signature — a decoded attestation that was
 * never verified is a database row in a cryptographic costume.
 */
export function verifyRecordAttestation(
  a: Association,
  subjectPage0: string,
  expectedHash: string,
): boolean {
  if (readRecordAttestation(a) !== expectedHash.toLowerCase()) return false;
  return verifyVouch(a, subjectPage0);
}

/**
 * A certifier co-signs a KINSHIP edge — a third-party `kin.edge` vouch about
 * `subjectPage0`. Identical in mechanism to any third-party `kinClaim`; named
 * for the intent, because "FamilySearch says this parent link is real" is the
 * common case and deserves a legible call site.
 */
export function familySearchKinVouch(
  fsSk: PrivateKey,
  subjectPage0: string,
  relation: KinRelation,
  counterpartPage0: string,
): Association {
  return kinClaim(fsSk, subjectPage0, relation, counterpartPage0);
}

export type VouchTier = 'certifier' | 'self' | 'peer' | 'invalid';

/** Build the trusted-key set from a certifier list, for {@link vouchTier}. */
export function trustedSet(certifiers: readonly Certifier[]): ReadonlySet<string> {
  return new Set(certifiers.map((c) => c.pubkey));
}

/**
 * Weigh an association's vouch, about `subjectPage0`, against the certifiers a
 * verifier trusts.
 *
 * - `invalid` — the signature does not verify for this subject (a lifted or
 *   forged leaf). Checked first: an unverified vouch has no tier.
 * - `certifier` — signed by a trusted certifier (e.g. FamilySearch).
 * - `self` — the subject vouched for themselves.
 * - `peer` — signed by someone else, untrusted-as-certifier (a relative's word).
 *
 * The verifier supplies the trust set, so "who counts as a certifier" is a local
 * policy decision, never baked into the substrate.
 */
export function vouchTier(
  a: Association,
  subjectPage0: string,
  trustedCertifiers: ReadonlySet<string>,
): VouchTier {
  if (!verifyVouch(a, subjectPage0)) return 'invalid';
  if (trustedCertifiers.has(a.vouchedBy)) return 'certifier';
  if (a.vouchedBy === subjectPage0) return 'self';
  return 'peer';
}
