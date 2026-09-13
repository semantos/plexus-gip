/**
 * Demo rail + demo issuer derivation for the paid-attestation prototype.
 *
 * ⚠️ NOT REAL SETTLEMENT. `MockRail` trusts a local flag where the real rail
 * (`@semantos/x402`) trusts the mined ledger. It exists so the portal logic runs
 * end-to-end offline; it must never be wired into anything that takes money.
 */

import { PrivateKey } from '@bsv/sdk';
import type { Settlement, SettlementVerifier } from './portal';

/** A settlement verifier you can drive by hand: `pay(nonce)` then `verify(nonce)`. */
export class MockRail implements SettlementVerifier {
  private readonly settled = new Map<string, Settlement>();

  /** Simulate an on-chain payment against an invoice settling to a finality (default `final`). */
  pay(invoiceNonce: string, finality: Settlement = 'final'): void {
    this.settled.set(invoiceNonce, finality);
  }

  verify(invoiceNonce: string, _expectedSat: number): Settlement {
    return this.settled.get(invoiceNonce) ?? 'none';
  }
}

/**
 * Derive a demo issuer key, ONLY to illustrate the custody model: the root never
 * signs; a scoped, non-invertible child does.
 *
 * ⚠️ THIS IS NOT THE PRODUCTION DERIVATION — it is a different key schedule, and
 * should not be read as the real one. The real org-node key is
 * `deriveOrgNodeSk(tier0, orgIndex)` in `@semantos/wallet`, which differs on every
 * structural axis:
 *   - it is a child of the org's **tier-0**, not the root (root → tier-0 → org-node);
 *   - **kdf-v4 keyed** HMAC(tier0Sk, …), not BRC-42 self-ECDH (kdf-v1);
 *   - scoped by the **WALLET_ORG** domain flag (260) + preimage `semantos-wallet-org`,
 *     addressed by a numeric `orgIndex` — not a free-text label;
 *   - its trust anchor is a **Model-B cert id** (`certIdOf`, 32 hex), not a raw pubkey;
 *   - it is recoverable via the wallet's recovery envelope and carries an
 *     `OrgBindingRecord`; none of that exists here.
 * (A cross-operator parent→child org — e.g. a child brain under an operator — uses
 * yet another shape: `mintChildNode`, kdf-v3 unkeyed off the parent root, challenge-gated.)
 *
 * We use a BRC-42 self-child here purely so the demo needs only `@bsv/sdk`. It
 * faithfully shows the *custody idea* (a passive observer can't invert the child to
 * the parent) and nothing else about the real key schedule.
 */
export function deriveDemoIssuer(fsRoot: PrivateKey, label = 'familysearch-org-attestation-issuer-1'): PrivateKey {
  return fsRoot.deriveChild(fsRoot.toPublicKey(), label);
}
