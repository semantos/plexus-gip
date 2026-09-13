/**
 * Delegated co-vouching — the trusted key and the signing key are never the same.
 *
 * The flat model ({@link ../social/familysearch!vouchTier} + `trustedSet`) has one
 * key do both jobs: a verifier trusts a certifier by putting THAT key in its
 * trusted set, and the certifier signs vouches with THAT SAME key. So the
 * high-value trust anchor is exposed on every signing path, rotating it breaks
 * every verifier's trust set, and running more than one signing desk is
 * impossible without trusting each desk key directly.
 *
 * Delegation splits the roles. The ANCHOR (FamilySearch's root / org identity —
 * the key a verifier trusts) signs a short certificate authorizing a NODE key;
 * the NODE signs the actual vouches; the anchor never touches a vouch. A verifier
 * trusts only the anchor, and accepts a node's vouch when a valid delegation
 * chains that node back to a trusted anchor.
 *
 * ## Why a signed delegation, and not a derivation proof
 *
 * The production node key (`deriveOrgNodeSk`, `@semantos/wallet`) is a KEYED
 * (kdf-v4) child of the org's tier-0, keyed precisely so an observer CANNOT link
 * the node back to the root from public keys. That unlinkability is deliberate —
 * which means the relationship is not publicly derivable and must be proven the
 * other way: the anchor SIGNS a statement binding the node. That signed statement
 * is the delegation here (the same role the wallet's `OrgBindingRecord` plays).
 * Rotation = issue a new delegation; multiple desks = multiple delegations under
 * one anchor; the verifier's trust set stays a single root either way.
 */

import type { PrivateKey } from '@bsv/sdk';
import { type Association, signAssociation, verifyVouch } from '../associations';

/** The association kind a delegation carries. */
export const DELEGATION_KIND = 'kin.delegation';

/** Default scope — "may co-vouch genealogy leaves on the anchor's behalf". */
export const DEFAULT_DELEGATION_PURPOSE = 'kin.vouch';

/** A resolved, cryptographically-verified delegation. */
export interface DelegationInfo {
  /** The trusted root / org-identity key that issued the delegation. */
  readonly anchor: string;
  /** The signing key it authorized. */
  readonly node: string;
  /** The scope it was granted. */
  readonly purpose: string;
}

const SEP = '|';

/**
 * The anchor authorizes `nodePubkey` to co-vouch on its behalf.
 *
 * Returned as an `Association` bound to the NODE key (the node is the "subject"
 * of the delegation), so a delegation cannot be re-pointed at a different node —
 * the same subject-binding every vouch relies on. The anchor's own key signs it
 * and is never used to sign a vouch.
 */
export function delegateSigner(
  anchorSk: PrivateKey,
  nodePubkey: string,
  purpose: string = DEFAULT_DELEGATION_PURPOSE,
): Association {
  const display = `${purpose}${SEP}${nodePubkey}`;
  return {
    kind: DELEGATION_KIND,
    display,
    vouchedBy: anchorSk.toPublicKey().toString(),
    signature: signAssociation(anchorSk, nodePubkey, DELEGATION_KIND, display),
  };
}

/**
 * Parse AND verify a delegation. Returns who authorized whom, for what — or null
 * if it is malformed or the anchor's signature does not check. A parsed-but-
 * unverified delegation is a forgeable claim, so this never returns one.
 */
export function readDelegation(d: Association): DelegationInfo | null {
  if (d.kind !== DELEGATION_KIND) return null;
  const i = d.display.indexOf(SEP);
  if (i <= 0) return null;
  const purpose = d.display.slice(0, i);
  const node = d.display.slice(i + 1);
  if (node.length === 0) return null;
  if (!verifyVouch(d, node)) return null; // the anchor really signed THIS node
  return { anchor: d.vouchedBy, node, purpose };
}

export type VouchTier = 'certifier' | 'self' | 'peer' | 'invalid';

/** What a verifier trusts, for {@link delegatedVouchTier}. */
export interface DelegatedTrust {
  /** The root / anchor keys the verifier trusts. Usually one. */
  readonly anchors: ReadonlySet<string>;
  /** Delegations the verifier has seen (carried in the holder's set, or published). */
  readonly delegations?: readonly Association[];
  /** If set, a delegation must carry this exact purpose to count. */
  readonly requirePurpose?: string;
}

/**
 * Weigh a vouch about `subjectPage0` where the signer may be a DELEGATED node
 * rather than the trusted anchor itself.
 *
 * - `invalid`   — the vouch signature does not verify for this subject.
 * - `certifier` — signed by a trusted anchor DIRECTLY, or by a node a trusted
 *                 anchor delegated (a valid delegation chains node → anchor).
 * - `self`      — the subject vouched for themselves.
 * - `peer`      — signed by someone with no path to a trusted anchor.
 *
 * A trusted-anchor key that ONLY ever issues delegations (never signs a vouch)
 * still yields `certifier` for its nodes' vouches — which is the whole point.
 */
export function delegatedVouchTier(
  a: Association,
  subjectPage0: string,
  trust: DelegatedTrust,
): VouchTier {
  if (!verifyVouch(a, subjectPage0)) return 'invalid';
  if (trust.anchors.has(a.vouchedBy)) return 'certifier'; // anchor signed directly
  for (const d of trust.delegations ?? []) {
    const info = readDelegation(d);
    if (info === null) continue;
    if (info.node !== a.vouchedBy) continue;
    if (!trust.anchors.has(info.anchor)) continue;
    if (trust.requirePurpose !== undefined && info.purpose !== trust.requirePurpose) continue;
    return 'certifier'; // delegated by a trusted anchor
  }
  if (a.vouchedBy === subjectPage0) return 'self';
  return 'peer';
}
