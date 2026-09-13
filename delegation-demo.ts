/**
 * Delegated co-vouching — runnable demo.
 *
 *     bun delegation-demo.ts
 *
 * Shows the key-hygiene model: FamilySearch's trusted ANCHOR key never signs a
 * vouch. It delegates a signing NODE, the node signs, and a verifier that trusts
 * only the anchor still reads the node's vouch as `certifier` — because a signed
 * delegation chains the node back to the anchor. Rotation, multiple desks, and a
 * forged delegation are all exercised. Everything runs against real signatures.
 */

import { PrivateKey } from '@bsv/sdk';
import {
  delegateSigner,
  delegatedVouchTier,
  familySearchKinVouch,
  readDelegation,
  vouchTier,
  trustedSet,
} from './src';

const key = (label: string): PrivateKey =>
  PrivateKey.fromString(
    Buffer.from(require('node:crypto').createHash('sha256').update(`gip-v2-demo/${label}`).digest()).toString('hex'), 16);
const pub = (k: PrivateKey): string => k.toPublicKey().toString();
const short = (p: string): string => `${p.slice(0, 10)}…${p.slice(-4)}`;
const h = (t: string): void => console.log(`\n\x1b[1m${t}\x1b[0m`);
const ok = (b: boolean): string => (b ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m');

// ── FamilySearch keys: a trusted anchor + signing desks (never the anchor) ─────
const anchor = key('fs-anchor');    // FamilySearch root / org identity — the ONLY trusted key
const desk1 = key('fs-desk-1');     // a signing node (derived, rotatable) — NOT trusted directly
const desk2 = key('fs-desk-2');     // a second desk / post-rotation node
const evil = key('impostor');       // an untrusted key that will try to self-delegate
const alice = key('alice'); const ALICE = pub(alice);
const mary = key('mary'); const MARY = pub(mary);

const anchors = new Set([pub(anchor)]);   // the verifier trusts exactly one root

console.log('\x1b[1m═══ Delegated co-vouch — anchor delegates, node signs, verifier trusts the anchor ═══\x1b[0m');
console.log(`  FS anchor (trusted)  ${short(pub(anchor))}   — never signs a vouch`);
console.log(`  desk-1 (signer)      ${short(pub(desk1))}   — not in the trust set`);

// ── 1. anchor delegates desk-1; desk-1 signs a kinship vouch ──────────────────
h('[1] Anchor issues a delegation; the desk signs the vouch');
const deleg1 = delegateSigner(anchor, pub(desk1), 'kin.vouch');
const vouch = familySearchKinVouch(desk1, ALICE, 'parent', MARY);
console.log(`  delegation: anchor → ${short(readDelegation(deleg1)?.node ?? '')}  purpose=${readDelegation(deleg1)?.purpose}`);
console.log(`  vouch.vouchedBy = ${short(vouch.vouchedBy)}  (the desk, not the anchor)`);

h('[2] Verifier trusts ONLY the anchor — the delegated vouch reads certifier');
const tier = delegatedVouchTier(vouch, ALICE, { anchors, delegations: [deleg1] });
console.log(`  delegatedVouchTier = ${tier} ${ok(tier === 'certifier')}`);

h('[3] Without the delegation, the same vouch is only a peer');
const noDeleg = delegatedVouchTier(vouch, ALICE, { anchors, delegations: [] });
console.log(`  delegatedVouchTier = ${noDeleg} ${ok(noDeleg === 'peer')}  — the desk key is not trusted on its own`);
console.log(`  (flat vouchTier agrees: ${vouchTier(vouch, ALICE, trustedSet([{ name: 'FS', pubkey: pub(anchor) }]))} — it only knows the anchor)`);

// ── 4. rotation / multiple desks: a new delegation, same anchor ───────────────
h('[4] Rotation & multiple desks — a second node under the same anchor');
const deleg2 = delegateSigner(anchor, pub(desk2), 'kin.vouch');
const vouch2 = familySearchKinVouch(desk2, ALICE, 'parent', MARY);
const rot = delegatedVouchTier(vouch2, ALICE, { anchors, delegations: [deleg1, deleg2] });
console.log(`  desk-2 vouch = ${rot} ${ok(rot === 'certifier')}  — trust set never changed; revoking = drop the delegation`);

// ── 5. a forged delegation from a non-anchor buys nothing ─────────────────────
h('[5] A forged delegation (self-signed by an impostor) does NOT confer trust');
const forged = delegateSigner(evil, pub(desk1), 'kin.vouch'); // "evil delegates desk-1"
const forgedTier = delegatedVouchTier(vouch, ALICE, { anchors, delegations: [forged] });
console.log(`  impostor-delegated vouch = ${forgedTier} ${ok(forgedTier === 'peer')}  — the delegation's anchor is not trusted`);

// ── 6. the anchor CAN still sign directly (backward compatible) ───────────────
h('[6] A direct anchor vouch still reads certifier (flat model is a subset)');
const direct = familySearchKinVouch(anchor, ALICE, 'parent', MARY);
const directTier = delegatedVouchTier(direct, ALICE, { anchors, delegations: [] });
console.log(`  anchor-signed vouch = ${directTier} ${ok(directTier === 'certifier')}`);

console.log('\n\x1b[1m═══ done — the trust anchor never signed a vouch; delegated nodes did ═══\x1b[0m');
