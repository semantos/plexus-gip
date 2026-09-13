/**
 * Genealogical Identity Protocol v2 — a runnable end-to-end walkthrough.
 *
 *     bun walkthrough.ts
 *
 * Prints each step of the protocol against freshly-derived demo keys, so you can
 * watch a lineage identity be built entirely from signed edges — no GEDCOM as
 * the substrate, no key derived from personal data. Pairs with this kit's
 * README. The L1 range proof is marked experimental/unaudited and says so at its
 * step.
 */

import { PrivateKey } from '@bsv/sdk';
import {
  L1_ZK_STATUS,
  type RecordModel,
  familySearchKinVouch,
  kinBondConsistent,
  proveNumericPredicate,
  predicateAttestation,
  recordAttestation,
  recordFromGedcomTree,
  recordHash,
  recordToKinClaims,
  recordToMarkdown,
  selfKinClaim,
  trustedSet,
  verifyAncestorPath,
  verifyNumericPredicate,
  verifyPredicateAttestation,
  verifyRecordAttestation,
  vouchTier,
} from './src';

/** Deterministic demo key from a label (so the output is stable and explainable). */
const key = (label: string): PrivateKey =>
  PrivateKey.fromString(
    Buffer.from(require('node:crypto').createHash('sha256').update(`gip-v2-demo/${label}`).digest()).toString('hex'),
    16,
  );
const pub = (k: PrivateKey): string => k.toPublicKey().toString();
const short = (p: string): string => `${p.slice(0, 10)}…${p.slice(-4)}`;
const h = (title: string): void => console.log(`\n\x1b[1m${title}\x1b[0m`);
const ok = (b: boolean): string => (b ? '\x1b[32m✓ true\x1b[0m' : '\x1b[31m✗ false\x1b[0m');

// ── the cast ────────────────────────────────────────────────────────────────
const alice = key('alice');
const mary = key('mary');       // Alice's mother
const grandma = key('grandma'); // Mary's mother
const fs = key('familysearch'); // the FamilySearch certifier (holds its key off-server)
const ALICE = pub(alice); const MARY = pub(mary); const GRANDMA = pub(grandma); const FS = pub(fs);

console.log('\x1b[1m═══ Genealogical Identity Protocol v2 — walkthrough ═══\x1b[0m');

h('[1] Roots — each person is a self-sovereign page-0 key (not derived from public genealogy)');
console.log(`  Alice        ${short(ALICE)}`);
console.log(`  Mary         ${short(MARY)}   (Alice's mother)`);
console.log(`  Grandma      ${short(GRANDMA)}   (Mary's mother)`);
console.log(`  FamilySearch ${short(FS)}   (certifier — signs, holds no one's keys)`);

h('[2] Kinship: a claim, then a bond (the GIP child→parent→child scheme, as two vouches)');
const aliceParentMary = selfKinClaim(alice, 'parent', MARY); // in Alice's set: "my parent is Mary"
const maryChildAlice = selfKinClaim(mary, 'child', ALICE);   // in Mary's set:  "my child is Alice"
console.log('  Alice signs:  parent → Mary');
console.log('  Mary  signs:  child  → Alice');
console.log(`  bond consistent (mutual, inverse relations)? ${ok(kinBondConsistent(aliceParentMary, ALICE, maryChildAlice, MARY))}`);

h('[3] FamilySearch co-signs the edge — attestor, not custodian');
const fsVouch = familySearchKinVouch(fs, ALICE, 'parent', MARY);
const trusted = trustedSet([{ name: 'FamilySearch', pubkey: FS }]);
console.log(`  vouchTier(FamilySearch edge)  = ${vouchTier(fsVouch, ALICE, trusted)}`);
console.log(`  vouchTier(Alice's self-edge)  = ${vouchTier(aliceParentMary, ALICE, trusted)}`);
console.log(`  vouchTier(FamilySearch edge, empty trust set) = ${vouchTier(fsVouch, ALICE, new Set())}  (trust is the verifier's, local)`);

h('[4] A record — biography canonicalised to GEDCOM X, addressed by recordHash');
const aliceRecord: RecordModel = {
  subject: ALICE,
  names: [{ given: 'Alice', surname: 'Ellis' }],
  facts: [{ type: 'birth', date: '1961-03-04', place: 'Perth, WA' }],
  relations: [{ relation: 'parent', counterpart: MARY }],
  sources: [{ repo: 'FamilySearch', id: 'KWZY-1AB' }],
};
const rh = recordHash(aliceRecord);
console.log(`  recordHash = ${rh}`);
console.log('  record document (Markdown + JSON frontmatter):');
console.log(recordToMarkdown(aliceRecord).split('\n').map((l) => `    ${l}`).join('\n'));

h('[5] FamilySearch attests the record hash (signs a digest, never holds the record)');
const recAtt = recordAttestation(fs, ALICE, rh);
console.log(`  verifyRecordAttestation(subject=Alice, hash) = ${ok(verifyRecordAttestation(recAtt, ALICE, rh))}`);

h('[6] Predicate attestation — L0: the certifier signs a computed property, the tree stays hidden');
const predAtt = predicateAttestation(fs, ALICE, 'gen-depth>=2');
console.log('  FamilySearch signs:  gen-depth>=2');
console.log(`  verifyPredicateAttestation = ${ok(verifyPredicateAttestation(predAtt, ALICE, 'gen-depth>=2'))}`);
console.log(`  vouchTier                  = ${vouchTier(predAtt, ALICE, trusted)}`);

h('[7] Numeric predicate — L1 self-proof: Alice proves it herself, NO attestor');
console.log(`  \x1b[33m⚠ experimental / unaudited ZK — status: ${L1_ZK_STATUS}\x1b[0m`);
const bornBefore = proveNumericPredicate('born-before<=1970', 1961n); // Alice born 1961
console.log('  Alice proves:  born-before<=1970  (without revealing the year)');
console.log(`  verifyNumericPredicate = ${ok(verifyNumericPredicate(bornBefore))}`);
try {
  proveNumericPredicate('born-before<=1900', 1961n);
  console.log('  a FALSE predicate proved?!  (should not happen)');
} catch {
  console.log('  a FALSE predicate (born-before<=1900) is unprovable — the prover refuses. ✓');
}

h('[8] Proof of Ancestor — a continuous path of signed edges, not a substring match');
const maryParentGrandma = selfKinClaim(mary, 'parent', GRANDMA);
const path = [
  { egoPub: ALICE, edge: aliceParentMary },  // Alice → Mary
  { egoPub: MARY, edge: maryParentGrandma },  // Mary  → Grandma
];
console.log('  path:  Alice → Mary → Grandma');
console.log(`  verifyAncestorPath (cryptographically continuous) = ${ok(verifyAncestorPath(path))}`);

h('[9] Legacy GEDCOM — bootstrap edges from an existing tree (relatives counter-sign later)');
const ged = [
  '0 HEAD', '1 SOUR FamilySearch',
  '0 @I1@ INDI', '1 NAME Alice /Ellis/', '1 BIRT', '2 DATE 4 MAR 1961', '1 FAMC @F1@',
  '0 @I2@ INDI', '1 NAME Mary /Ellis/', '1 FAMS @F1@',
  '0 @I3@ INDI', '1 NAME Ted /Ellis/', '1 FAMS @F1@',
  '0 @F1@ FAM', '1 HUSB @I3@', '1 WIFE @I2@', '1 CHIL @I1@',
  '0 TRLR',
].join('\n');
const map = new Map<string, string>([['I2', MARY]]); // only Mary has enrolled so far
const imported = recordFromGedcomTree(ged, 'I1', ALICE, map);
if (imported !== null) {
  console.log(`  imported @I1@:  ${imported.model.names[0]?.given} ${imported.model.names[0]?.surname}`);
  console.log(`  resolved relations:   ${imported.model.relations.map((r) => `${r.relation}→${short(r.counterpart)}`).join(', ')}`);
  console.log(`  unresolved (invite):  ${imported.unresolved.map((r) => `${r.relation}→${r.counterpartXref}`).join(', ') || '(none)'}`);
  const claims = recordToKinClaims(imported.model, alice);
  console.log(`  → ${claims.length} self-asserted kin.edge claim(s) ready for relatives to counter-sign`);
}

console.log('\n\x1b[1m═══ done — every step above ran against real signatures ═══\x1b[0m');
console.log('Next: try the FamilySearch certifier CLI —  bun cli.ts --help   (see README.md)');
