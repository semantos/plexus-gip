/**
 * Paid-attestation portal — prototype.
 *
 * The runnable shape of `docs/GIP-V2-PAID-ATTESTATION.md`: FamilySearch
 * charges to ISSUE an attestation over an x402-style handshake. This is the
 * portal LOGIC — the 402 invoice, the nonce↔claim binding, issue-only-on-final,
 * one-payment-one-attestation, and the real-time vs async paths. It is real and
 * tested.
 *
 * Two things are behind PORTS so the prototype runs without a live chain, and so
 * the real pieces drop in unchanged:
 *   - {@link SettlementVerifier} — "did this invoice settle, and how final?"
 *     The real implementation is `@semantos/x402`'s on-chain verifier; the demo
 *     ships a mock (`./mock-rail`).
 *   - {@link IssueSigner} — signs a claim into an attestation leaf with the
 *     FamilySearch issuer key. Per the design that key is an ORG NODE derived off
 *     FamilySearch's root (`deriveOrgNodeSk`) — the root stays in the vault, only
 *     this scoped, rotatable node reaches the portal. `orgNodeSigner` builds one
 *     from an injected `PrivateKey`; the demo shows the derivation.
 *
 * What is deliberately NOT here: on-chain settlement, key storage/rotation, HTTP
 * (see `./server`), and any suggestion this is production-ready. Verification is
 * not here either — it stays free and offline in the verifier's hands.
 */

import type { PrivateKey } from '@bsv/sdk';
import {
  type Association,
  type KinRelation,
  familySearchKinVouch,
  predicateAttestation,
  readDelegation,
  recordAttestation,
} from '../src';
import { createHash, randomBytes } from 'node:crypto';

/** What is being attested — a discriminated union over the three attestation kinds. */
export type AttestClaim =
  | { readonly kind: 'kin'; readonly relation: KinRelation; readonly counterpart: string }
  | { readonly kind: 'record'; readonly recordHash: string }
  | { readonly kind: 'predicate'; readonly predicate: string };

export interface AttestRequest {
  /** The subject's page-0 public key — who the attestation is about and bound to. */
  readonly subject: string;
  readonly claim: AttestClaim;
}

/**
 * Settlement finality, mirroring `core/protocol-types/src/payments` — the portal
 * issues ONLY on `final`. `provisional`/`unproven` are not "probably fine"; a
 * reversed or unchecked payment must never leave a signed attestation standing.
 */
export type Settlement = 'final' | 'provisional' | 'unproven' | 'none';

export interface SettlementVerifier {
  /** How final is the payment against this invoice? (real: @semantos/x402; demo: ./mock-rail) */
  verify(invoiceNonce: string, expectedSat: number): Settlement | Promise<Settlement>;
}

export interface IssuedLeaf {
  readonly kind: AttestClaim['kind'];
  readonly association: Association;
}

export interface IssueSigner {
  /** The org-node public key that actually SIGNS the leaves (the attestation desk). */
  readonly certifier: string;
  /**
   * The root/org identity a verifier trusts — the ANCHOR. When set, `certifier`
   * is a delegated node under it (never the anchor itself), so the trust set is a
   * single root and the signing key is rotatable. Absent = flat model, where the
   * signer IS the trusted key.
   */
  readonly anchor?: string;
  /** The anchor→node delegation to present alongside the leaves, so a verifier trusts the anchor. */
  readonly delegation?: Association;
  sign(subject: string, claim: AttestClaim): IssuedLeaf;
}

/** Per-issuance price, scaling with the work (design §5): kin < record < predicate. */
export function priceFor(claim: AttestClaim): number {
  switch (claim.kind) {
    case 'kin': return 100;
    case 'record': return 500;
    case 'predicate': return 1000;
  }
}

export interface Invoice {
  readonly invoiceNonce: string;
  readonly amountSat: number;
  readonly subject: string;
  readonly kind: AttestClaim['kind'];
  /** Binds the invoice to THIS exact claim, so a cheap payment can't redeem a dear one. */
  readonly claimDigest: string;
}

function claimDigest(req: AttestRequest): string {
  return createHash('sha256').update(JSON.stringify({ s: req.subject, c: req.claim })).digest('hex');
}

export type RedeemResult =
  | { readonly status: 'issued'; readonly leaf: IssuedLeaf }
  | { readonly status: 'queued'; readonly ticket: string }
  | { readonly status: 'payment_required'; readonly settlement: Settlement }
  | { readonly status: 'unknown_invoice' }
  | { readonly status: 'already_redeemed' };

export type PollResult =
  | { readonly status: 'issued'; readonly leaf: IssuedLeaf }
  | { readonly status: 'pending' }
  | { readonly status: 'unknown_ticket' };

export interface PortalOptions {
  readonly verifier: SettlementVerifier;
  readonly signer: IssueSigner;
  /** Claim kinds that go to async review/offline-signing instead of instant issue. */
  readonly reviewKinds?: ReadonlySet<AttestClaim['kind']>;
}

/**
 * The portal. In-memory stores make it a prototype, not a service — but the state
 * transitions are the real ones: an invoice is issued once, redeemed once, and a
 * leaf is only ever produced against a `final` settlement.
 */
export class AttestationPortal {
  private readonly invoices = new Map<string, { req: AttestRequest; amountSat: number }>();
  private readonly consumed = new Set<string>();
  private readonly queue = new Map<string, { req: AttestRequest; leaf?: IssuedLeaf }>();

  constructor(private readonly opts: PortalOptions) {}

  /** The node key that signs the leaves. NOT what a verifier trusts when delegated — use {@link anchor}. */
  get certifier(): string {
    return this.opts.signer.certifier;
  }

  /** The root a verifier should trust: the anchor when delegated, else the signing key itself. */
  get anchor(): string {
    return this.opts.signer.anchor ?? this.opts.signer.certifier;
  }

  /** The anchor→node delegation to hand a verifier (with the leaves), if this issuer is delegated. */
  get delegation(): Association | undefined {
    return this.opts.signer.delegation;
  }

  /** Step 1 — the 402: mint an invoice bound to this exact claim. */
  requestAttestation(req: AttestRequest): Invoice {
    const invoiceNonce = randomBytes(16).toString('hex');
    const amountSat = priceFor(req.claim);
    this.invoices.set(invoiceNonce, { req, amountSat });
    return { invoiceNonce, amountSat, subject: req.subject, kind: req.claim.kind, claimDigest: claimDigest(req) };
  }

  /** Step 2 — redeem: verify a FINAL settlement, then issue (or queue for async). */
  async redeem(invoiceNonce: string): Promise<RedeemResult> {
    const inv = this.invoices.get(invoiceNonce);
    if (inv === undefined) return { status: 'unknown_invoice' };
    if (this.consumed.has(invoiceNonce)) return { status: 'already_redeemed' };

    const settlement = await this.opts.verifier.verify(invoiceNonce, inv.amountSat);
    if (settlement !== 'final') return { status: 'payment_required', settlement };

    // Final: consume the nonce now — one payment, one attestation, no replay.
    this.consumed.add(invoiceNonce);

    if (this.opts.reviewKinds?.has(inv.req.claim.kind) === true) {
      const ticket = randomBytes(12).toString('hex');
      this.queue.set(ticket, { req: inv.req });
      return { status: 'queued', ticket };
    }
    return { status: 'issued', leaf: this.opts.signer.sign(inv.req.subject, inv.req.claim) };
  }

  /** Async fallback — FamilySearch signs a queued request offline; then the holder polls. */
  signPending(ticket: string): boolean {
    const q = this.queue.get(ticket);
    if (q === undefined || q.leaf !== undefined) return false;
    q.leaf = this.opts.signer.sign(q.req.subject, q.req.claim);
    return true;
  }

  poll(ticket: string): PollResult {
    const q = this.queue.get(ticket);
    if (q === undefined) return { status: 'unknown_ticket' };
    return q.leaf !== undefined ? { status: 'issued', leaf: q.leaf } : { status: 'pending' };
  }
}

/**
 * An issuer that signs with an org-node key (the FamilySearch attestation desk).
 *
 * In production `issuerSk` would be a real org-node key — `deriveOrgNodeSk(tier0,
 * orgIndex)` in `@semantos/wallet` (kdf-v4 keyed, off tier-0, WALLET_ORG domain,
 * Model-B cert id) — so the portal only ever holds a scoped, rotatable child and
 * the root stays in the vault. ⚠️ The demo does NOT reproduce that derivation; see
 * `deriveDemoIssuer` in `./mock-rail` for the stand-in and how it differs.
 */
export function orgNodeSigner(issuerSk: PrivateKey): IssueSigner {
  return {
    certifier: issuerSk.toPublicKey().toString(),
    sign(subject: string, claim: AttestClaim): IssuedLeaf {
      switch (claim.kind) {
        case 'kin':
          return { kind: 'kin', association: familySearchKinVouch(issuerSk, subject, claim.relation, claim.counterpart) };
        case 'record':
          return { kind: 'record', association: recordAttestation(issuerSk, subject, claim.recordHash) };
        case 'predicate':
          return { kind: 'predicate', association: predicateAttestation(issuerSk, subject, claim.predicate) };
      }
    },
  };
}

/**
 * A DELEGATED issuer — the key-hygiene model. `nodeSk` signs the leaves, but a
 * verifier trusts the ANCHOR that issued `delegation`; the anchor's own key never
 * reaches the portal. The portal hands out `anchor` (what to trust) and
 * `delegation` (the proof the node speaks for the anchor), and a relying party
 * weighs leaves with `delegatedVouchTier({ anchors: {anchor}, delegations: [delegation] })`.
 *
 * Rotating the desk is a new delegation under the same anchor; the verifier's
 * trust set never changes. Throws if the delegation does not verify or does not
 * authorize this node — a portal must never advertise a broken chain.
 */
export function delegatedOrgNodeSigner(nodeSk: PrivateKey, delegation: Association): IssueSigner {
  const node = nodeSk.toPublicKey().toString();
  const info = readDelegation(delegation);
  if (info === null) throw new Error('delegation does not verify');
  if (info.node !== node) throw new Error('delegation does not authorize this node');
  return { ...orgNodeSigner(nodeSk), anchor: info.anchor, delegation };
}
