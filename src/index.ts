/**
 * GIP v2 kit — the public surface, carved from semantos-core.
 *
 * This barrel re-exports exactly the Genealogical Identity Protocol v2 modules,
 * standing in for `@semantos/protocol-types/identity` in the full monorepo. The
 * module sources under `src/` are unmodified copies; only this barrel and the
 * two runnable entry points (`walkthrough.ts`, `cli.ts`) are kit-specific.
 */

// Edge substrate — identity as a set of signed associations (merkle-committed).
export {
  ASSOCIATION_KINDS,
  ASSOCIATION_SCHEMA_V1,
  type Association,
  associationValue,
  buildAssociationSet,
  discloseAssociation,
  readDisclosedAssociation,
  signAssociation,
  verifyVouch,
  vouchPreimage,
} from './associations';

// Social login leaves (proof-of-human by breadth), incl. FamilySearch OIDC.
export {
  FAMILYSEARCH_DISCOVERY,
  FAMILYSEARCH_ISSUER,
  SOCIAL_PROVIDERS,
  type SocialCertFields,
  type SocialCertResult,
  type SocialProviderId,
  humanityEvidence,
  meetsHumanityThreshold,
  socialAssociation,
  socialCertFields,
} from './social/providers';

// GEDCOM X → RecordModel mapper (FamilySearch's tree data → our edges).
export {
  type GedcomXDocument,
  type GedcomXPerson,
  type GedcomXRelationship,
  recordFromGedcomX,
  relationsForPerson,
} from './social/gedcom-x';

// Kinship edges — claims, bonds, ancestor paths.
export {
  KIN_INVERSE,
  KIN_RELATIONS,
  type AncestorHop,
  type KinEdge,
  type KinRelation,
  encodeKinDisplay,
  isKinEdge,
  kinBondConsistent,
  kinClaim,
  parseKinDisplay,
  readKinEdge,
  selfKinClaim,
  verifyAncestorPath,
} from './social/kinship';

// Record codec — GEDCOM X canonical + recordHash, Markdown/XHTML/legacy.
export {
  type RecordFact,
  type RecordModel,
  type RecordName,
  type RecordRelation,
  recordFromGedcom551,
  recordFromMarkdown,
  recordHash,
  recordToGedcom551,
  recordToKinClaims,
  recordToMarkdown,
  recordToXhtml,
  toGedcomX,
} from './social/record';

// Legacy GEDCOM tree import.
export {
  type GedcomImportResult,
  type GedcomTree,
  type ProvisionalRelation,
  parseGedcomTree,
  recordFromGedcomTree,
  relationsForIndividual,
} from './social/gedcom';

// FamilySearch as attestor + trust weighing.
export {
  RECORD_ATTESTATION_KIND,
  type Certifier,
  type VouchTier,
  familySearchKinVouch,
  readRecordAttestation,
  recordAttestation,
  trustedSet,
  verifyRecordAttestation,
  vouchTier,
} from './social/familysearch';

// Delegated co-vouching — anchor delegates a signing node; verifier trusts the anchor.
export {
  DEFAULT_DELEGATION_PURPOSE,
  DELEGATION_KIND,
  type DelegatedTrust,
  type DelegationInfo,
  delegateSigner,
  delegatedVouchTier,
  readDelegation,
} from './social/delegation';

// L0 predicate attestations.
export {
  PREDICATE_KIND,
  type Predicate,
  type PredicateOp,
  encodePredicate,
  parsePredicate,
  predicateAttestation,
  readPredicateAttestation,
  verifyPredicateAttestation,
} from './social/predicate';

// L1 self-proven numeric predicates — ⚠ EXPERIMENTAL / UNAUDITED (L1_ZK_STATUS).
export {
  L1_ZK_STATUS,
  type Commitment,
  type RangeProof,
  commit,
  proveRange,
  verifyRange,
} from './zk/range-proof';
export {
  type NumericPredicateProof,
  proveNumericPredicate,
  verifyNumericPredicate,
} from './zk/numeric-predicate';
