/**
 * FamilySearch signing — the off-server certifier operations, CLI-ready.
 *
 * FamilySearch holds its key OFF the server, like every certifier in
 * `certify.ts`, and runs these to produce a PORTABLE SIGNED LEAF: either a
 * `kin.edge` co-vouch ("this parent→child link matches an authoritative
 * record") or a `kin.record` attestation over a record's hash. Each leaf is
 * bound to the subject's page-0 key, so it is safe to hand back out-of-band —
 * the holder folds it into their own association set and commits that set
 * themselves. Nothing is posted from here: a certifier's only outputs are a
 * signed leaf and its own public key, which a verifier adds to the
 * trusted-certifier set it weighs with `vouchTier`.
 *
 * This lives outside `certify.ts` on purpose. That file dispatches on
 * `process.argv` at import time; this module has no side effects and no I/O
 * (the key is passed in), so it can be unit-tested directly. `certify.ts` does
 * the key load (`loadCertifier`) and prints what these return.
 */

import { PrivateKey, PublicKey } from '@bsv/sdk';
import {
  type Association,
  type KinRelation,
  KIN_RELATIONS,
  familySearchKinVouch,
  predicateAttestation,
  recordAttestation,
} from './src';

/** Validate a relation token from CLI input against the known vocabulary. */
export function asKinRelation(s: string): KinRelation {
  if (Object.prototype.hasOwnProperty.call(KIN_RELATIONS, s)) return s as KinRelation;
  throw new Error(`unknown kin relation "${s}" — one of ${Object.keys(KIN_RELATIONS).join(', ')}`);
}

/** Normalise a public key from CLI input, with a clear error naming the field. */
function validPubkey(hex: string, what: string): string {
  try {
    return PublicKey.fromString(hex).toString();
  } catch {
    throw new Error(`${what} is not a valid public key: ${hex}`);
  }
}

/** A portable leaf: the signed association plus the certifier key that signed it. */
export interface FsLeaf {
  /** FamilySearch's public key — add it to the verifier's trusted-certifier set. */
  readonly certifier: string;
  readonly kind: 'kin.vouch' | 'record.attestation' | 'predicate.attestation';
  /** The subject page-0 key the leaf is bound to. */
  readonly subject: string;
  readonly association: Association;
}

function envelope(
  fsSk: PrivateKey,
  kind: FsLeaf['kind'],
  subject: string,
  association: Association,
): string {
  const leaf: FsLeaf = { certifier: fsSk.toPublicKey().toString(), kind, subject, association };
  return JSON.stringify(leaf, null, 2);
}

/**
 * `fs-vouch-kin <subjectPubkey> <relation> <counterpartPubkey>`
 *
 * FamilySearch co-signs a kinship edge about the subject: "the subject's
 * <relation> is <counterpart>." A third-party `kin.edge` vouch.
 */
export function runFsVouchKin(fsSk: PrivateKey, argv: readonly string[]): string {
  const [subject, relation, counterpart] = argv.filter((a) => !a.startsWith('--'));
  if (subject === undefined || relation === undefined || counterpart === undefined) {
    throw new Error('usage: fs-vouch-kin <subjectPubkey> <relation> <counterpartPubkey>');
  }
  const subjectPub = validPubkey(subject, 'subject');
  const counterpartPub = validPubkey(counterpart, 'counterpart');
  const assoc = familySearchKinVouch(fsSk, subjectPub, asKinRelation(relation), counterpartPub);
  return envelope(fsSk, 'kin.vouch', subjectPub, assoc);
}

/**
 * `fs-attest-record <subjectPubkey> <recordHash>`
 *
 * FamilySearch attests that the subject's record hashes to <recordHash> (the
 * value `recordHash()` produced from the canonical GEDCOM X form). The hash is
 * opaque here — the certifier signs a digest, not a document.
 */
export function runFsAttestRecord(fsSk: PrivateKey, argv: readonly string[]): string {
  const [subject, recordHash] = argv.filter((a) => !a.startsWith('--'));
  if (subject === undefined || recordHash === undefined) {
    throw new Error('usage: fs-attest-record <subjectPubkey> <recordHash>');
  }
  const subjectPub = validPubkey(subject, 'subject');
  const assoc = recordAttestation(fsSk, subjectPub, recordHash); // throws on a malformed hash
  return envelope(fsSk, 'record.attestation', subjectPub, assoc);
}

/**
 * `fs-attest-predicate <subjectPubkey> <predicate>`
 *
 * FamilySearch attests that a computed PREDICATE holds over the subject's
 * lineage — the L0 rung of the ZK predicate-proof ladder. `<predicate>` is a
 * canonical string like `gen-depth>=3` or `ancestry-region:scotland-highland>=1`
 * (see `../../core/protocol-types/src/social/predicate`). Quote it in the shell,
 * since `>=` and friends are redirections:
 *
 *     bun certify.ts fs-attest-predicate 02ab… 'gen-depth>=3'
 *
 * The certifier signs the property, revealing nothing of the tree behind it.
 */
export function runFsAttestPredicate(fsSk: PrivateKey, argv: readonly string[]): string {
  const [subject, predicate] = argv.filter((a) => !a.startsWith('--'));
  if (subject === undefined || predicate === undefined) {
    throw new Error("usage: fs-attest-predicate <subjectPubkey> <predicate>  (quote it, e.g. 'gen-depth>=3')");
  }
  const subjectPub = validPubkey(subject, 'subject');
  const assoc = predicateAttestation(fsSk, subjectPub, predicate); // throws on a malformed predicate
  return envelope(fsSk, 'predicate.attestation', subjectPub, assoc);
}
