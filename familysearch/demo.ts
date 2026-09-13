/**
 * FamilySearch tree-data bridge — runnable demo (mock Tree API, real signatures).
 *
 *     bun familysearch/demo.ts
 *
 * Shows the notary path end to end: the subject's FS OIDC session anchors a
 * page-0 key; the bridge reads their (mocked) FamilySearch tree, maps the GEDCOM
 * X, and re-attests it — a record attestation + one kinship vouch per resolved
 * relation, with the unresolved relatives listed and a provenance receipt.
 * Pairs with `docs/GIP-V2-FS-INTEGRATION-SEAM.md`.
 */

import { PrivateKey } from '@bsv/sdk';
import {
  type GedcomXDocument,
  readKinEdge,
  trustedSet,
  verifyRecordAttestation,
  vouchTier,
} from '../src';
import { MockTreeApi } from './tree-api';
import { bridgeAttest } from './bridge';

const pub = (k: PrivateKey) => k.toPublicKey().toString();
const short = (p: string) => `${p.slice(0, 10)}…${p.slice(-4)}`;
const ok = (b: boolean) => (b ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m');

// FamilySearch's root stays in the vault; the bridge signs with a derived node.
const fsRoot = PrivateKey.fromString('f5'.repeat(32), 16);
const bridgeSk = fsRoot.deriveChild(fsRoot.toPublicKey(), 'familysearch-tree-bridge-1');

// The holder (proved control of their page-0 via the FS OIDC leaf) + relatives.
const jane = PrivateKey.fromRandom(); const JANE = pub(jane);
const mary = PrivateKey.fromRandom(); const MARY = pub(mary);
const john = PrivateKey.fromRandom(); const JOHN = pub(john);

// The (mock) FamilySearch tree: Jane (I1), parents John (I3) + Mary (I2),
// sibling Bob (I4, not yet enrolled), child Kid (I6, not yet enrolled).
const tree: GedcomXDocument = {
  persons: [
    { id: 'I1', names: [{ nameForms: [{ parts: [
      { type: 'http://gedcomx.org/Given', value: 'Jane' }, { type: 'http://gedcomx.org/Surname', value: 'Ellis' },
    ] }] }], facts: [{ type: 'http://gedcomx.org/Birth', date: { original: '4 March 1961' }, place: { original: 'Perth' } }] },
    { id: 'I2' }, { id: 'I3' }, { id: 'I4' }, { id: 'I6' },
  ],
  relationships: [
    { type: 'http://gedcomx.org/ParentChild', person1: { resource: '#I3' }, person2: { resource: '#I1' } },
    { type: 'http://gedcomx.org/ParentChild', person1: { resource: '#I2' }, person2: { resource: '#I1' } },
    { type: 'http://gedcomx.org/ParentChild', person1: { resource: '#I3' }, person2: { resource: '#I4' } },
    { type: 'http://gedcomx.org/ParentChild', person1: { resource: '#I1' }, person2: { resource: '#I6' } },
  ],
};

const treeApi = new MockTreeApi(new Map([['I1', tree]]));
const trusted = trustedSet([{ name: 'FamilySearch', pubkey: pub(bridgeSk) }]);

console.log('\x1b[1m═══ FamilySearch tree-data bridge — demo ═══\x1b[0m  \x1b[33m(tree mocked; signatures real)\x1b[0m');
console.log(`FS root      ${short(pub(fsRoot))}  (never signs)`);
console.log(`bridge node  ${short(pub(bridgeSk))}  (derived; what verifiers trust)`);

const res = await bridgeAttest(
  bridgeSk, treeApi,
  { subjectPage0: JANE, fsPersonId: 'I1', fsUserId: 'fsuser-jane' },
  new Map([['I3', JOHN], ['I2', MARY]]), // only Jane's parents have enrolled
  '2026-09-10T00:00:00Z',
);

if (res === null) {
  console.log('bridge returned null (person not found)');
} else {
  console.log(`\n\x1b[1mrecord attestation\x1b[0m  hash ${short(res.provenance.recordHash)}`);
  console.log(`  verify = ${ok(verifyRecordAttestation(res.record, JANE, res.provenance.recordHash))}`);
  console.log(`\n\x1b[1mkinship vouches\x1b[0m (${res.edges.length})`);
  for (const e of res.edges) {
    const k = readKinEdge(e);
    console.log(`  ${k?.relation} → ${short(k?.counterpart ?? '')}   tier=${vouchTier(e, JANE, trusted)} ${ok(vouchTier(e, JANE, trusted) === 'certifier')}`);
  }
  console.log(`\n\x1b[1munresolved\x1b[0m (invite): ${res.unresolved.map((r) => `${r.relation}→${r.counterpartXref}`).join(', ')}`);
  console.log(`\n\x1b[1mprovenance\x1b[0m  ${res.provenance.source}  user=${res.provenance.fsUserId}  person=${res.provenance.fsPersonId}  read=${res.provenance.readAtIso}`);
}

console.log('\n\x1b[1m═══ done — the bridge re-attested only what the tree returned ═══\x1b[0m');
