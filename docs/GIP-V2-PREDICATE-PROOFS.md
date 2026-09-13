# GIP v2 — ZK predicate proofs over the lineage graph (scoping)

**Status:** scoping / design note (no code) — decisions for sign-off in §9
**Scopes:** the last unbuilt GIP v2 item — the original GIP's *"self-sovereign data markets… prove genetic provenance and demographic suitability without disclosing PII"* (2024 GIP §Identity Verification / Knowledge Assets)
**Builds on:** `social/kinship.ts` (signed edges) · `social/record.ts` (`recordHash` over canonical GEDCOM X) · `social/familysearch.ts` (attestor + `vouchTier`) · `field-tree` (L8 merkle disclosure) · `@bsv/sdk` `Schnorr` (DLEQ ZKP)
**Relates to:** [`GIP-V2-GENEALOGICAL-IDENTITY.md`](GIP-V2-GENEALOGICAL-IDENTITY.md) §9, `bsv-blockchain/identity` (bsv-blockchain/identity ZK)

> Note on the word "proof": `proofs/lean/**` and `PROOFS-WALLET-EXTENSION-PLAN.md` are **formal (Lean) verification** of opcode semantics — a different sense entirely. This note is about **cryptographic zero-knowledge proofs** over genealogical data. They do not touch.

---

## 0. One-liner

We want a holder to prove a *statement about their lineage* — "I descend ≥3 generations from verified Highland-Scottish ancestry" — **without revealing the names, dates, or edges** behind it. The whole difficulty is one fact: our lineage data is signed with **secp256k1 ECDSA** and committed with **SHA-256 merkle trees**, and both are *hostile* to general-purpose ZK circuits. So this is not "pick a ZK library"; it is a **cost/trust ladder** with three rungs — attestor-signed predicates (cheap, trusts FamilySearch), commitment range-proofs (moderate, self-provable, numeric only), and general ZK over the signed graph (expensive, trustless, research). The recommendation is to climb only as far as a real market requires.

## 1. The goal, restated

The 2024 GIP promised "secondary data markets" where a person monetizes *anonymized* lineage — proving a buyer that their data has the demanded **genetic provenance** and **demographic suitability** without disclosing who they are. Stripped of the GEDCOM framing, that is exactly: **selective *predicate* disclosure over the kinship graph** — reveal a computed *property*, never the underlying records or edges. GIP v2 already does selective *leaf* disclosure (`discloseAssociation`); predicates are the same move one level up, over *derived* facts.

## 2. Predicate taxonomy (with the genealogical examples that motivate each)

| Class | Example predicate | Shape |
|---|---|---|
| **Membership** | "I hold a FamilySearch-attested `birth` fact" | ∃ leaf of kind K (have today, but reveals the leaf) |
| **Numeric / range** | "born before 1970"; "≥3 documented generations"; "≥5 ancestors born in region R" | value ∈ [a,b], or a count ≥ n |
| **Depth / path** | "I descend from ancestor X"; "unbroken attested chain of depth ≥ n" | ∃ signed path root→…→X |
| **Relatedness degree** | "I am within 4 meioses of person Y" / "I am NOT within 4 meioses of Y" | shortest-path length over the graph, with sign |
| **Attribute over a set** | "≥K% of my traced ancestry is from region R" | aggregate over facts on the path set |
| **Non-membership / non-relatedness** | "no shared grandparent with Y" (conflict-of-interest, market suitability) | ∄ path / ∄ shared node |

The data-market cases the GIP cares about are mostly **numeric/range**, **relatedness degree**, and **attribute-over-a-set** — provenance and suitability, not identity.

## 3. The substrate reality — why this is hard, precisely

What a lineage claim actually *is*, cryptographically:

- a **kinship edge** = an ECDSA (secp256k1, DER) signature over a BRC-42 domain preimage (`vouchPreimage`), committed in a **SHA-256** merkle field-tree per person;
- a **record** = canonical GEDCOM X → `recordHash` (SHA-256), attested by a FamilySearch **ECDSA** signature;
- FamilySearch's authority = an **ECDSA** signature the verifier already trusts (`vouchTier`).

A ZK predicate over that data has to prove statements about **secp256k1 ECDSA verifications** and **SHA-256 merkle paths** *inside a proof system*. Both are the classic worst case for SNARKs: secp256k1 is a **non-native field** (the proof system's field ≠ the curve's field, so every group op costs thousands of constraints), and SHA-256 is **bit-oriented** (tens of thousands of constraints per hash). A depth-8 ancestor path could mean 8 ECDSA verifications + dozens of SHA-256 compressions in-circuit — minutes to prove, on a good day.

**What we already have (and its limits):**
- `field-tree` merkle **selective disclosure** — proves a leaf is committed, but *reveals the leaf*. Not zero-knowledge for a predicate.
- `@bsv/sdk` **`Schnorr`** — a DLEQ ZKP: prove `S = a·B` given `A = a·G` without revealing `a`. This is powerful for **key-relationship** predicates (per-relying-party pseudonym unlinkability, "this pseudonym derives from my page-0", correct-ECDH) — the bsv-blockchain/identity pattern — but it says **nothing** about ranges, paths, or regions. It is a proof about one discrete log, not about arbitrary computation.
- **No** Bulletproofs, Pedersen commitments, SNARK, or STARK anywhere in the repo. Everything past L0/DLEQ is net-new.

## 4. The cost/trust ladder — three rungs

### L0 — Attestor-signed predicates (cheap · trusts FamilySearch · buildable now)

FamilySearch already sees the whole tree. So instead of proving a predicate *over* the signed data, have the attestor **sign the predicate itself**: a new attestation whose `display` is a canonical predicate string — `gen-depth>=3`, `ancestry-region:scotland-highland>=1`, `born-before:1970` — bound to the subject key, exactly like `recordAttestation`.

- **Mechanism:** a `kin.predicate` association kind; `predicateAttestation(fsSk, subject, predicate)`; verified with the existing `verifyVouch` + weighed by `vouchTier`. **This is a ~1-day extension of `familysearch.ts`** — no new crypto.
- **Reveals:** the predicate, and that a trusted attestor computed it. Reveals **nothing** of the underlying tree.
- **Trust:** the buyer trusts FamilySearch's computation, not math. For a *data market* that is often exactly right — the market already prices FamilySearch's authority.
- **Covers:** nearly every data-market predicate in §2 (range, depth, region-share, relatedness-to-a-named-cohort).

### L1 — Commitment + range/set proofs (moderate · self-provable · numeric only)

For predicates a person should prove **without trusting an attestor to assert them**, commit the numeric value in a **Pedersen commitment** and attach a **Bulletproof range proof**. Bulletproofs live on the **same secp256k1 group** BSV uses, need **no trusted setup**, and are log-sized — the one advanced primitive that fits our curve cleanly.

- **Covers:** birth-year ranges (age ≥ 18, born-before), and any predicate reducible to *a range over a committed integer* — including "generation depth ≥ n" or "region-ancestor count ≥ k" **if** that integer is itself a value some party commits (which reintroduces a trust question about who counts correctly — see §5).
- **Reveals:** the commitment and the range bounds; not the value.
- **Build:** net-new Bulletproofs implementation (or a vetted secp256k1 Bulletproofs lib inlined per the artifact/library discipline) + a commitment-linking step tying the committed value to an attested fact. Non-trivial but bounded, no setup ceremony.

### L2 — General ZK over the signed graph (expensive · trustless · research)

The trustless ideal: prove path/relatedness/region predicates over the *actual* ECDSA-signed edges + SHA-256 merkle, revealing only the predicate. Options, none cheap:

- **STARK** — no trusted setup, post-quantum, but large proofs and still must express SHA-256/secp256k1 in an AIR;
- **SNARK (PLONK/Groth16)** — small proofs, but a universal/trusted setup **and** the non-native secp256k1 cost; variable-length paths need either padding to a max depth or **recursion** (prove one hop, fold);
- **the escape hatch → §5.**

L2 is a genuine research track. It should not be started speculatively.

## 5. The pragmatic bridge — make the data SNARK-friendly *at rest*

Most of L2's cost is proving SHA-256 and secp256k1 *that were chosen for other reasons*. If, alongside the ECDSA/SHA-256 record, the attestor (or the holder) **also commits the lineage facts under a SNARK-friendly hash** (e.g. **Poseidon**) in a parallel Merkle tree, then depth/region/relatedness predicates become tractable ZK **without proving SHA-256 in-circuit** — you prove membership in the Poseidon tree instead.

- **Trade:** a second commitment structure, and the verifier must trust *that the Poseidon tree faithfully mirrors the signed data* — which pushes the trust back toward an attestor (L0-ish) unless the mirror itself is proven. It is the standard identity-ZK move (it is essentially what bsv-blockchain/identity's zk-proofs-and-poc does with its own commitments), and it is the only realistic path to *self-provable* graph predicates.
- **Decision it forces:** do we introduce a parallel Poseidon-committed lineage tree as a first-class artifact? (§9-b)

## 6. Privacy properties and leaks, per rung

- **All rungs** leak *that a proof was produced* and *which predicate was asked* — the request itself is a signal (a buyer learns you can plausibly satisfy the query). Unlinkability across buyers needs per-RP pseudonyms (the `Schnorr` DLEQ + a `pid = PRF(s, buyer)` à la bsv-blockchain/identity) layered on top; that is a separate axis from the predicate proof.
- **L0** additionally reveals the attestor and that it vouched — usually fine, sometimes itself identifying (a tiny attested cohort).
- **L1** reveals the commitment and bounds; repeated proofs against the *same* commitment are linkable unless re-blinded.
- **L2** reveals only the predicate — the point — at the cost.
- **The leaf-count leak** already noted in `associations` still applies to any merkle path a proof references.

## 7. Interop / prior art

`bsv-blockchain/identity` (its `zk-proofs-and-poc.md`) is the reference design and is BRC-42/secp256k1-native like us: per-RP ZK pseudonyms (`pid = PRF(s, scope)`), a personhood **nullifier** `n`, ZK selective disclosure. Two concrete borrowings:

- its **PRF-pseudonym + Schnorr DLEQ** pattern is the unlinkability layer of §6, and we already have the `Schnorr` primitive to build it;
- its **nullifier** is the anti-sybil primitive a *data market* wants — "one real lineage per seller" so a person can't resell the same anonymized ancestry as many distinct cohorts. It rhymes with our `extension_nullifier` seam (see `bsv-blockchain/identity`). (§9-d)

## 8. Recommendation — phase by demand, not by ambition

1. **Phase 1 — L0 attestor predicates.** A `kin.predicate` attestation + `vouchTier` weighing. Delivers the GIP's data-market value *now*, composes with everything built, ~1 day, zero new crypto. **Do this first, and possibly only this** until a buyer demands trustlessness.
2. **Phase 2 — L1 Bulletproof numeric predicates.** Self-provable age/birth-year/committed-count, no attestor trust, no setup. Build when a numeric predicate needs to stand *without* FamilySearch asserting it.
3. **Phase 3 — L2 general ZK**, gated on (a) a real market that pays for trustlessness *and* (b) the §5 Poseidon-mirror decision or an external ZK partner. Treat as research, not a roadmap item.

The unlinkability layer (Schnorr DLEQ + PRF pseudonyms) and the anti-sybil nullifier are **orthogonal** and can be added at any phase if the market needs unlinkable sellers.

## 9. Load-bearing decisions (for sign-off)

- **(a) Attestor-mediated vs trustless emphasis.** Is the near-term product an L0 *attested-predicate* market (trust FamilySearch, ship now), or do we invest in L1/L2 self-proof? Recommendation: **L0 now**, L1 when forced.
- **(b) SNARK-friendly parallel commitment (§5).** Introduce a Poseidon-committed lineage tree to make graph predicates ZK-tractable — or stay ECDSA/SHA-256-only? **DECIDED — defer:** see [`GIP-V2-POSEIDON-MIRROR-DECISION.md`](GIP-V2-POSEIDON-MIRROR-DECISION.md). No mirror now; when demand arrives, prefer the attestor-signed mirror (L0-fidelity trust + ZK privacy) over the fully-trustless bridge, and adopt a vetted ZK stack rather than hand-roll.
- **(c) Proof-system choice** for L1 (Bulletproofs — recommended, no setup, our curve) and, if ever, L2 (STARK vs SNACK+recursion).
- **(d) Anti-sybil nullifier for markets.** Adopt the bsv-blockchain/identity nullifier ("one lineage per seller") or leave markets sybil-permissive? Only if a market launches.
- **(e) Where predicate proofs live** — a brain endpoint (like the `did` resolver), a holder-side wallet capability, or a boomspace market cartridge. (Not the Lean `proofs/` tree — §Note.)

## 10. Non-goals

- Building any ZK circuit in this note — it is scoping; Phase 1 (L0) is the only thing recommended for immediate build, and it needs none.
- Re-rooting lineage data off ECDSA/SHA-256 (the signed edges + `recordHash` are the identity; §5 *adds* a mirror, it does not replace).
- Per-relying-party unlinkability as part of the predicate proof — it is a separate, composable layer (§6).
- Claiming trustless graph predicates are cheap today — they are not, and §3 is the honest reason.
