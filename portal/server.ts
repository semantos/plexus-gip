/**
 * Paid-attestation portal — HTTP prototype (Bun.serve).
 *
 *     bun portal/server.ts      # then curl it
 *
 * Exposes the 402 handshake so you can drive it by hand:
 *
 *   POST /attest   { subject, claim }            → 402 { invoiceNonce, amountSat, … }
 *   POST /dev/settle { invoiceNonce, finality? } → DEV-ONLY: simulate the on-chain payment
 *   POST /redeem   { invoiceNonce }              → 200 { leaf } | 402 | 202 { ticket } | 404 | 409
 *   GET  /poll?ticket=…                          → 200 { leaf } | 202 pending | 404
 *   POST /sign-pending { ticket }                → DEV-ONLY: stand in for FamilySearch signing offline
 *
 * ⚠️ Prototype: settlement is mocked (`./mock-rail`) and there is NO real payment
 * rail, no auth, and in-memory state. Do not deploy. `/dev/*` routes exist only
 * because there is no chain here — they vanish the moment `@semantos/x402` is wired.
 */

import { PrivateKey } from '@bsv/sdk';
import { type KinRelation, delegateSigner } from '../src';
import { type AttestClaim, AttestationPortal, delegatedOrgNodeSigner } from './portal';
import { MockRail, deriveDemoIssuer } from './mock-rail';

// FIXED demo keys so the anchor, node, and delegation are stable across restarts.
// A real deployment loads FamilySearch's root / org identity as the ANCHOR and
// derives the signing node with `deriveOrgNodeSk`; the anchor signs a delegation
// and never signs a leaf.
const fsAnchor = PrivateKey.fromString('f5'.repeat(32), 16);   // trusted root / org identity
const issuerNode = deriveDemoIssuer(fsAnchor);                 // delegated signing desk (stand-in)
const delegation = delegateSigner(fsAnchor, issuerNode.toPublicKey().toString());
const rail = new MockRail();
const portal = new AttestationPortal({
  verifier: rail,
  signer: delegatedOrgNodeSigner(issuerNode, delegation),
  reviewKinds: new Set<AttestClaim['kind']>(['predicate']),
});

const json = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body, null, 2), { status, headers: { 'content-type': 'application/json' } });

function parseClaim(c: unknown): AttestClaim | null {
  if (typeof c !== 'object' || c === null) return null;
  const o = c as Record<string, unknown>;
  if (o.kind === 'kin' && typeof o.relation === 'string' && typeof o.counterpart === 'string') {
    // Cast the relation; the signer validates it for real (throws on an unknown relation).
    return { kind: 'kin', relation: o.relation as KinRelation, counterpart: o.counterpart };
  }
  if (o.kind === 'record' && typeof o.recordHash === 'string') return { kind: 'record', recordHash: o.recordHash };
  if (o.kind === 'predicate' && typeof o.predicate === 'string') return { kind: 'predicate', predicate: o.predicate };
  return null;
}

const HELP = {
  service: 'paid-attestation portal (prototype)',
  anchor: portal.anchor,          // trust THIS — the root / org identity
  signingNode: portal.certifier,  // signs the leaves; trusted only via the delegation
  delegation: portal.delegation,  // anchor → node; present it with a leaf to verify against the anchor
  note: 'settlement is MOCKED; /dev/* routes stand in for a real x402 rail. Trust the ANCHOR, not the signing node.',
  routes: {
    'POST /attest': '{ subject, claim:{kind:"kin",relation,counterpart} | {kind:"record",recordHash} | {kind:"predicate",predicate} } → 402 invoice',
    'POST /dev/settle': '{ invoiceNonce, finality?="final" }  (DEV)',
    'POST /redeem': '{ invoiceNonce } → leaf | 402 | ticket',
    'GET /poll?ticket=': '→ leaf | pending',
    'POST /sign-pending': '{ ticket }  (DEV: FamilySearch signs the queued item offline)',
  },
};

const server = Bun.serve({
  port: Number(process.env.PORT ?? 4021),
  async fetch(req) {
    const url = new URL(req.url);
    const body = async (): Promise<Record<string, unknown>> => {
      try { return (await req.json()) as Record<string, unknown>; } catch { return {}; }
    };

    if (req.method === 'GET' && url.pathname === '/') return json(HELP);

    if (req.method === 'POST' && url.pathname === '/attest') {
      const b = await body();
      const claim = parseClaim(b.claim);
      if (typeof b.subject !== 'string' || claim === null) return json({ error: 'need { subject, claim }' }, 400);
      const invoice = portal.requestAttestation({ subject: b.subject, claim });
      return json({ ...invoice, pay: 'settle amountSat against invoiceNonce, then POST /redeem' }, 402);
    }

    if (req.method === 'POST' && url.pathname === '/dev/settle') {
      const b = await body();
      if (typeof b.invoiceNonce !== 'string') return json({ error: 'need { invoiceNonce }' }, 400);
      rail.pay(b.invoiceNonce, (b.finality as 'final' | 'provisional' | 'unproven') ?? 'final');
      return json({ settled: b.invoiceNonce, finality: b.finality ?? 'final' });
    }

    if (req.method === 'POST' && url.pathname === '/redeem') {
      const b = await body();
      if (typeof b.invoiceNonce !== 'string') return json({ error: 'need { invoiceNonce }' }, 400);
      const r = await portal.redeem(b.invoiceNonce);
      switch (r.status) {
        case 'issued': return json({ anchor: portal.anchor, delegation: portal.delegation, ...r.leaf }, 200);
        case 'queued': return json({ status: 'queued', ticket: r.ticket, poll: `/poll?ticket=${r.ticket}` }, 202);
        case 'payment_required': return json({ status: 'payment_required', settlement: r.settlement }, 402);
        case 'unknown_invoice': return json({ error: 'unknown invoice' }, 404);
        case 'already_redeemed': return json({ error: 'already redeemed — one payment, one attestation' }, 409);
      }
    }

    if (req.method === 'GET' && url.pathname === '/poll') {
      const ticket = url.searchParams.get('ticket') ?? '';
      const p = portal.poll(ticket);
      if (p.status === 'issued') return json({ anchor: portal.anchor, delegation: portal.delegation, ...p.leaf }, 200);
      if (p.status === 'pending') return json({ status: 'pending' }, 202);
      return json({ error: 'unknown ticket' }, 404);
    }

    if (req.method === 'POST' && url.pathname === '/sign-pending') {
      const b = await body();
      if (typeof b.ticket !== 'string') return json({ error: 'need { ticket }' }, 400);
      return json({ signed: portal.signPending(b.ticket) });
    }

    return json({ error: 'not found', see: 'GET /' }, 404);
  },
});

console.log(`paid-attestation portal (prototype) on http://localhost:${server.port}`);
console.log(`anchor (trust this):        ${portal.anchor}`);
console.log(`signing node (delegated):   ${portal.certifier}`);
console.log('⚠ settlement is MOCKED — use POST /dev/settle to simulate payment. GET / for routes.');
