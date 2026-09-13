/**
 * Paid-attestation portal — runnable end-to-end demo.
 *
 *     bun portal/demo.ts
 *
 * Drives the portal through every path against real signatures (settlement is
 * mocked — see `./mock-rail`): the 402 handshake, real-time issue on final
 * settlement, refusal on a non-final payment, the async review lane, and the
 * one-payment-one-attestation replay guard. Pairs with
 * `docs/GIP-V2-PAID-ATTESTATION.md`.
 */

import { PrivateKey } from '@bsv/sdk';
import {
  readKinEdge,
  delegateSigner,
  delegatedVouchTier,
  verifyPredicateAttestation,
  verifyRecordAttestation,
} from '../src';
import { AttestationPortal, delegatedOrgNodeSigner } from './portal';
import { MockRail, deriveDemoIssuer } from './mock-rail';

const pub = (k: PrivateKey): string => k.toPublicKey().toString();
const short = (p: string): string => `${p.slice(0, 10)}…${p.slice(-4)}`;
const h = (t: string): void => console.log(`\n\x1b[1m${t}\x1b[0m`);
const ok = (b: boolean): string => (b ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m');

// ── FamilySearch's keys — the ANCHOR delegates a signing node; the anchor never signs ─
const fsAnchor = PrivateKey.fromRandom();               // FS root / org identity — the ONLY trusted key
const issuerNode = deriveDemoIssuer(fsAnchor);          // a signing desk (derived stand-in), rotatable
const delegation = delegateSigner(fsAnchor, pub(issuerNode)); // the anchor authorizes the node
const rail = new MockRail();
const portal = new AttestationPortal({
  verifier: rail,
  signer: delegatedOrgNodeSigner(issuerNode, delegation),
  reviewKinds: new Set(['predicate']), // computed predicates go to async review
});
// A verifier trusts ONLY the anchor, and is handed the delegation alongside the leaves.
const trust = { anchors: new Set([portal.anchor]), delegations: portal.delegation ? [portal.delegation] : [] };

// ── the holder and a relative ────────────────────────────────────────────────
const alice = PrivateKey.fromRandom(); const ALICE = pub(alice);
const mary = PrivateKey.fromRandom(); const MARY = pub(mary);

console.log('\x1b[1m═══ Paid-attestation portal — prototype demo ═══\x1b[0m  \x1b[33m(settlement mocked; not for production)\x1b[0m');
h('[keys] The FS anchor delegates a signing node; the anchor itself never signs a leaf');
console.log(`  FS anchor (trusted)  ${short(portal.anchor)}   (delegates; never signs a leaf)`);
console.log(`  issuer node (signs)  ${short(portal.certifier)}   (delegated desk, rotatable; demo stand-in, not the real deriveOrgNodeSk shape)`);
console.log('  a verifier trusts the ANCHOR and is handed the delegation with each leaf');

// ── 1. real-time: kinship co-vouch ───────────────────────────────────────────
h('[1] Real-time — FamilySearch co-vouches a kinship edge, paid');
{
  const inv = portal.requestAttestation({ subject: ALICE, claim: { kind: 'kin', relation: 'parent', counterpart: MARY } });
  console.log(`  → 402  ${inv.amountSat} sat   nonce ${short(inv.invoiceNonce)}   (claim bound: ${short(inv.claimDigest)})`);
  rail.pay(inv.invoiceNonce, 'final');           // holder settles on-chain (mocked)
  const r = await portal.redeem(inv.invoiceNonce);
  if (r.status === 'issued') {
    const edge = readKinEdge(r.leaf.association);
    console.log(`  → issued: kin.edge ${edge?.relation}→${short(edge?.counterpart ?? '')}`);
    const tier = delegatedVouchTier(r.leaf.association, ALICE, trust);
    console.log(`  verify: delegatedVouchTier = ${tier} ${ok(tier === 'certifier')}   (trusting the anchor, via its delegation — not the node key)`);
    const bare = delegatedVouchTier(r.leaf.association, ALICE, { anchors: new Set([portal.anchor]), delegations: [] });
    console.log(`  without the delegation:    ${bare} ${ok(bare === 'peer')}   (the node key alone is not trusted)`);
  } else console.log(`  unexpected: ${r.status}`);
}

// ── 2. real-time: record attestation ─────────────────────────────────────────
h('[2] Real-time — FamilySearch attests a record hash, paid');
{
  const recordHash = 'a'.repeat(64);
  const inv = portal.requestAttestation({ subject: ALICE, claim: { kind: 'record', recordHash } });
  console.log(`  → 402  ${inv.amountSat} sat`);
  rail.pay(inv.invoiceNonce, 'final');
  const r = await portal.redeem(inv.invoiceNonce);
  if (r.status === 'issued') {
    console.log(`  → issued: record attestation   verify = ${ok(verifyRecordAttestation(r.leaf.association, ALICE, recordHash))}`);
  } else console.log(`  unexpected: ${r.status}`);
}

// ── 3. refusal: payment not final ────────────────────────────────────────────
h('[3] Refusal — a provisional (reversible) payment does NOT get an attestation');
{
  const inv = portal.requestAttestation({ subject: ALICE, claim: { kind: 'kin', relation: 'parent', counterpart: MARY } });
  rail.pay(inv.invoiceNonce, 'provisional');      // paid, but not mined/final
  const r = await portal.redeem(inv.invoiceNonce);
  console.log(`  → ${r.status}${r.status === 'payment_required' ? ` (settlement: ${r.settlement})` : ''}  ${ok(r.status === 'payment_required')}  — issue only on final`);
}

// ── 4. async fallback: predicate goes to review, signed offline, delivered ────
h('[4] Async fallback — a computed predicate is paid, queued for review, then signed offline');
{
  const inv = portal.requestAttestation({ subject: ALICE, claim: { kind: 'predicate', predicate: 'gen-depth>=3' } });
  console.log(`  → 402  ${inv.amountSat} sat`);
  rail.pay(inv.invoiceNonce, 'final');
  const r = await portal.redeem(inv.invoiceNonce);
  if (r.status === 'queued') {
    console.log(`  → queued: ticket ${short(r.ticket)}   poll: ${portal.poll(r.ticket).status}`);
    portal.signPending(r.ticket);                 // FamilySearch signs offline after review
    const p = portal.poll(r.ticket);
    if (p.status === 'issued') {
      console.log(`  → delivered: predicate attestation   verify = ${ok(verifyPredicateAttestation(p.leaf.association, ALICE, 'gen-depth>=3'))}`);
    }
  } else console.log(`  unexpected: ${r.status}`);
}

// ── 5. replay guard: one payment, one attestation ────────────────────────────
h('[5] Replay guard — a settled invoice cannot be redeemed twice');
{
  const inv = portal.requestAttestation({ subject: ALICE, claim: { kind: 'kin', relation: 'parent', counterpart: MARY } });
  rail.pay(inv.invoiceNonce, 'final');
  const first = await portal.redeem(inv.invoiceNonce);
  const second = await portal.redeem(inv.invoiceNonce);
  console.log(`  first: ${first.status}   second: ${second.status}  ${ok(first.status === 'issued' && second.status === 'already_redeemed')}`);
}

console.log('\n\x1b[1m═══ done — leaves verified against the trusted ANCHOR via the node’s delegation; the anchor never signed ═══\x1b[0m');
console.log('HTTP server:  bun portal/server.ts   ·   Design: docs/GIP-V2-PAID-ATTESTATION.md');
