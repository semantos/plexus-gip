# Paid attestation — FamilySearch charges to issue, via x402

**Status:** design note (no code) — decisions in §8
**Builds on:** `social/familysearch.ts` (the attestations) · `deriveOrgNodeSk` (org key derivation off the org anchor) · `did:bsv` (root as a resolvable id) · an x402 payment rail with settlement finality
**Relates to:** [`GIP-V2-GENEALOGICAL-IDENTITY.md`](GIP-V2-GENEALOGICAL-IDENTITY.md) §7, [`GIP-V2-PREDICATE-PROOFS.md`](GIP-V2-PREDICATE-PROOFS.md)

---

## 0. Summary

FamilySearch can charge for **issuing** an attestation — a kinship co-vouch, a record attestation, or an L0 predicate — over **x402**: a request returns `402 Payment Required` with an invoice, the payer settles on-chain, and the signed leaf is returned. It signs with a **key derived off its own Plexus root org identity** (an org node, not a standalone key): the root stays in FamilySearch's vault, a scoped rotatable node signs at the portal. Delivery is a **real-time automated portal by default, with an async fallback** for review or offline signing. **Verification stays free and offline**, and payment data never enters the attestation — the invoice nonce is the only link.

This is the original GIP's "self-sovereign data market," realised at the attestor: FamilySearch earns by lending its authority, per issuance.

## 1. What is priced, and what is not

Payment gates **issuance** — the work FamilySearch does to check a fact against its tree and sign it. Payment does **not** gate **verification**: any relying party checks a leaf with `verifyRecordAttestation` / `verifyPredicateAttestation` / `vouchTier` offline, for free, forever. FamilySearch earns on the *mint*, not on every *read* — which is both the honest split and the scalable one (a widely-verified attestation does not meter FamilySearch to death).

## 2. The issuance flow

```
holder ──▶ POST /attest { subject, claim }         # "co-vouch my parent edge" / "attest gen-depth>=3"
       ◀── 402 Payment Required { invoiceNonce, amountSat, ... }
holder ──▶ settle on x402 (BSV)
server ──▶ verify settlement is FINAL (mined), not provisional  (§8-f)
       ◀── 200 { the signed attestation leaf }
```

The **`invoiceNonce` binds the payment to this exact issuance** — one payment, one attestation, for exactly this `subject` + `claim`. It is the same per-request 402 nonce the payments layer already uses to stop a settlement being replayed against a second invoice.

## 3. The signing key is a node in FamilySearch's own Plexus org

This is the load-bearing design choice, and it resolves the key-custody tension a live paid endpoint otherwise creates (a signing key on an internet-facing box vs. the "attestor holds no keys online" stance).

FamilySearch runs **its own org identity** — a Plexus org DAG rooted in its own identity, exactly the page-0 / org-binding structure (`deriveOrgNodeSk` derives org nodes off a root). So:

- **The root stays in the vault.** The attestation-issuing key at the portal is a **derived org node** — `deriveOrgNodeSk(root, …)` scoped to "genealogy attestation issuance." The root org key never touches the portal.
- **Rotation is cheap.** If the portal is compromised, FamilySearch rotates the issuer *node* without moving the root — and, crucially, without every verifier having to update a trust list (see below).
- **The org chart governs authority.** Which org node may issue which attestation kind is a role in FamilySearch's org chart (a "genealogy-attestor" role/branch), the same `AUTHORITY`/`ROLE_ASSIGNMENT` edges the org binding already models. Different desks, different scoped keys, one root.

### Trust one root, not a key list

Because the issuer key is *derived under the FamilySearch root*, a verifier trusts **FamilySearch's root org identity** — ideally addressed as a `did:bsv` (`did-bsv.ts`) — and accepts any attestation whose signing key proves it is a legitimate org node beneath that root (via the org binding / a short derivation-or-cert chain). So `vouchTier`'s trusted set is **one entry — the FamilySearch root** — not a churn-prone list of individual signing keys. Key rotation and multiple issuing desks become invisible to verifiers. This is the payoff of "keys derived off the FamilySearch root org," and it is why that steer matters beyond custody.

> Interop note: this is precisely the Plexus org-chart / "beside Okta" positioning applied to an outside institution — FamilySearch operating *its own* org identity, not enrolling in ours.

## 4. Delivery — automated portal by default, async fallback

**Primary — real-time portal.** The portal signs automatically on verified settlement and returns the leaf in the same exchange. This is acceptable precisely *because* the signing key is a derived, role-scoped org node (§3), not the root: an online key whose blast radius is bounded and rotatable.

**Fallback — async.** When the portal cannot sign automatically, the same endpoint degrades to queued issuance: pay → request accepted with a claim ticket → FamilySearch signs when ready → leaf delivered (poll, webhook, or a MessageBox drop). The async lane covers three real cases:

1. **manual review** for a high-assurance attestation FamilySearch will not automate;
2. **an offline-signing policy** for certain attestation kinds (root-adjacent keys kept fully off-line);
3. **portal downtime** — payments still queue rather than fail.

The two modes share **one issuance contract and one leaf shape**: a consumer cannot tell a portal-signed leaf from an offline-signed one, and never needs to. Async is a degraded mode of the same endpoint, not a separate product. (Payment on the async path settles the same way; only the signing is deferred — never charge without eventually delivering or refunding.)

## 5. Pricing

Per issuance, and the fee can scale with the work:

| Attestation | Work | Relative cost |
|---|---|---|
| kinship co-vouch (`familySearchKinVouch`) | check one edge against the tree | low |
| record attestation (`recordAttestation`) | check a whole record's facts | medium |
| computed predicate (L0, `predicateAttestation`) | traverse the tree to evaluate `gen-depth>=n`, region shares, relatedness | higher |

**Who pays** is open (§8-e): the holder seeking FamilySearch's vouch on their own edge/record, or a data-market buyer sponsoring the attestation of a cohort. The x402 invoice amount is the knob.

## 6. Separation of concerns (kept clean)

- **Verification is free and offline.** `vouchTier` / `verify*` never call FamilySearch; a paid endpoint exists only for issuance.
- **Payment data stays out of the attestation.** The leaf carries `{kind, display, vouchedBy, signature}` and nothing about the payment; the `invoiceNonce` links payment↔issuance server-side only. A verifier learns *who vouched what*, never *what was paid*.
- **One payment, one attestation.** The nonce prevents a single settlement from minting many leaves.

## 7. What exists vs. what is new

**Exists:** the attestations (`familysearch.ts`); org key derivation (`deriveOrgNodeSk`); `did:bsv` for the root; x402 as a first-class rail; settlement finality (the payments module).

**New:** the issuance **portal endpoint** (402 handshake → verify → sign → return); wiring the **issuer org-node key** + role→attestation-kind authorization; the **402-invoice binding for attestations** (reuse the payments nonce); the **async queue** + delivery (poll/webhook/MessageBox); and — since the brain does not yet carry `@semantos/x402` — the **settlement verifier** wherever the portal runs.

## 8. Load-bearing decisions

- **(a) DECIDED — key custody = derived org node at the portal, root in the vault.** FamilySearch runs its own Plexus org; the issuer key is `deriveOrgNodeSk(root, …)`, scoped and rotatable. (Per the project steer.)
- **(b) DECIDED — delivery = real-time portal primary, async fallback**, one issuance contract. (Per the steer.)
- **(c) DECIDED — trust model = trust the FamilySearch *root* org identity (a `did:bsv`), accept any org node proven beneath it.** Follows from (a); keeps `vouchTier`'s trusted set to one entry and makes rotation invisible to verifiers.
- **(d) OPEN — pricing model** (flat vs. per-work-tier vs. subscription for high-volume buyers).
- **(e) OPEN — who pays by default** (attested holder vs. data-market buyer).
- **(f) OPEN — the finality bar.** BSV is final when mined; the payments layer distinguishes `final` / `provisional` / `unproven`. Recommendation: **issue only on `final`** — issuing against a provisional/unproven settlement lets a reversed or unverified payment leave a signed attestation standing.

## 9. Non-goals

- Charging for **verification** — it is free and offline, always.
- Putting payment data **inside** the attestation — the nonce links them server-side; the leaf reveals nothing.
- Letting the portal hold the FamilySearch **root** — it holds a derived, scoped, rotatable node only.
- Issuing on a **non-final** settlement (§8-f).
- Building any of this here — it is a design note; the portal, the issuer-key wiring, and the async queue are the follow-on.
