/**
 * The FamilySearch tree-data bridge — the notary that re-attests what it read.
 *
 * The tree-data half of `GIP-V2-FS-INTEGRATION-SEAM.md` §3, option 2. Because the
 * Family Tree API returns UNSIGNED GEDCOM X (a third party cannot verify a tree
 * fact without calling FamilySearch), the bridge reads it — through the read-only
 * {@link TreeApi} port — maps it with `recordFromGedcomX`, and RE-ATTESTS it with
 * a bridge key. (In production that key would be a real org node — see the seam
 * note; the demos pass an ordinary key, NOT the production `deriveOrgNodeSk` shape,
 * which `portal/mock-rail.ts` documents.) The result is a set of signed leaves plus
 * a provenance receipt.
 *
 * ## Trust, stated plainly
 *
 * These attestations are worth exactly "the bridge faithfully relayed what
 * FamilySearch's API returned for this subject." They are pinned to the
 * subject's own OIDC session ({@link BridgeSession}) — the same FS login that
 * produced the identity leaf proved control of `subjectPage0` — so the vouch
 * reads "the FS account that proved control of page-0 X read this from the tree
 * at time T", and the raw provenance is kept. It is a notary, not a proof that
 * FamilySearch itself signed anything (it does not — that is the FS-as-signer
 * upgrade). Verification of the leaves stays free and offline.
 */

import type { PrivateKey } from '@bsv/sdk';
import {
  type Association,
  type ProvisionalRelation,
  familySearchKinVouch,
  recordAttestation,
  recordFromGedcomX,
  recordHash,
} from '../src';
import type { TreeApi } from './tree-api';

/** The subject's authenticated context — from the FS OIDC identity leaf. */
export interface BridgeSession {
  /** Page-0 key the FS login OIDC-proved control of. What the leaves bind to. */
  readonly subjectPage0: string;
  /** The subject's person id in the FamilySearch tree — what the API is read by. */
  readonly fsPersonId: string;
  /** The OIDC `user_id` that proved control of `subjectPage0`. Recorded in provenance. */
  readonly fsUserId: string;
}

/** The notary receipt — what was read, by whom, when. Not part of any leaf. */
export interface BridgeProvenance {
  readonly certifier: string; // the bridge/issuer key that re-attested
  readonly source: 'familysearch-tree';
  readonly fsUserId: string;
  readonly fsPersonId: string;
  readonly recordHash: string;
  readonly readAtIso: string;
}

export interface BridgeResult {
  /** `recordAttestation` over the mapped record's hash. */
  readonly record: Association;
  /** One `familySearchKinVouch` per resolved kinship relation. */
  readonly edges: readonly Association[];
  /** Relatives in the tree with no page-0 key yet — who to invite. */
  readonly unresolved: readonly ProvisionalRelation[];
  readonly provenance: BridgeProvenance;
}

/**
 * Read the subject's FamilySearch tree and re-attest it with `bridgeSk`.
 *
 * `idToPage0` maps FamilySearch person ids to the page-0 keys of relatives who
 * have enrolled; the rest come back in `unresolved`, never fabricated. `nowIso`
 * is a parameter, not a clock read, so a run is replayable. Returns null when the
 * person is not found or the subject key is malformed.
 */
export async function bridgeAttest(
  bridgeSk: PrivateKey,
  treeApi: TreeApi,
  session: BridgeSession,
  idToPage0: ReadonlyMap<string, string>,
  nowIso: string = new Date().toISOString(),
): Promise<BridgeResult | null> {
  const doc = await treeApi.readPerson(session.fsPersonId);
  if (doc === null) return null;

  const imported = recordFromGedcomX(doc, session.fsPersonId, session.subjectPage0, idToPage0);
  if (imported === null) return null;
  const { model, unresolved } = imported;

  const rh = recordHash(model);
  const record = recordAttestation(bridgeSk, session.subjectPage0, rh);
  const edges = model.relations.map((r) =>
    familySearchKinVouch(bridgeSk, session.subjectPage0, r.relation, r.counterpart),
  );

  return {
    record,
    edges,
    unresolved,
    provenance: {
      certifier: bridgeSk.toPublicKey().toString(),
      source: 'familysearch-tree',
      fsUserId: session.fsUserId,
      fsPersonId: session.fsPersonId,
      recordHash: rh,
      readAtIso: nowIso,
    },
  };
}
