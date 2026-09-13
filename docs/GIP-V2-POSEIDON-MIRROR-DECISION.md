# Decision — the Poseidon-mirror question for L2 (§9-b)

**Status:** DECISION (no code) — resolves [`GIP-V2-PREDICATE-PROOFS.md`](GIP-V2-PREDICATE-PROOFS.md) §9-b
**Decides:** whether to introduce a SNARK-friendly (Poseidon) parallel commitment over the lineage graph to make trustless L2 graph predicates tractable
**Relates to:** [`GIP-V2-PREDICATE-PROOFS.md`](GIP-V2-PREDICATE-PROOFS.md) §5, `bsv-blockchain/identity`, the L1 build (#2015, `zk/range-proof.ts`)

---

## 0. Decision

**Defer. Do not build a Poseidon mirror now.** When a paying use case actually needs graph predicates (descent, relatedness, region) the current rungs cannot serve, build the **attestor-signed mirror (option B below) first** — it is the smaller, honest step and matches the trust the market already extends to FamilySearch. Reserve the **fully-trustless bridge-proven mirror (option C)** for the rare use case that specifically cannot tolerate trusting the attestor for the mirror's fidelity. Either way, when the time comes, **adopt a vetted ZK stack — do not hand-roll it** (the L1 experience, #2015, is the reason). The signed edges + `recordHash` remain the identity; any mirror is additive and derived, never the root.

## 1. The question

§5 of the scoping note observed that L2 (trustless ZK over path/relatedness/region predicates) is expensive because it must verify **secp256k1 ECDSA + SHA-256 merkle** in-circuit — the worst case for SNARKs. The proposed escape: also commit the lineage facts under a **SNARK-friendly hash (Poseidon)** in a parallel Merkle tree, and prove predicates over *that* instead of proving SHA-256 in-circuit. §9-b asked: introduce that parallel tree as a first-class artifact, or stay ECDSA/SHA-256-only and accept that trustless graph predicates are out of reach?

## 2. It is not a binary — there are three options, with different trust models

The framing "mirror or no mirror" hides the real variable, which is **who is trusted for the mirror's fidelity to the signed data.**

| | What it is | Who computes the predicate | Trust for fidelity | Cost | ZK privacy of the graph |
|---|---|---|---|---|---|
| **A. No mirror** (today) | graph predicates only via L0: the attestor signs each specific predicate | the attestor | attestor (per predicate) | shipped | none — verifier sees the predicate the attestor signed |
| **B. Attestor-signed mirror** | attestor commits the lineage under Poseidon and signs the root once; provers prove predicates over it in ZK | **the prover, locally** | attestor (once, for the root) | Poseidon primitive + a Merkle mirror + ZK circuits — but **no in-circuit ECDSA** | **yes** — verifier learns only the predicate |
| **C. Bridge-proven mirror** | as B, but the mirror's faithful re-commitment of the signed data is itself proven in-circuit | the prover | **no one — math** | B **plus** the in-circuit ECDSA/SHA-256 bridge proof (the expensive thing the mirror was meant to avoid) | yes |

The load-bearing realisation: **a mirror only escapes in-circuit ECDSA by accepting attestor-fidelity trust (B).** Make it trustless (C) and you re-incur exactly the cost the mirror was supposed to remove — you have only *moved* it from "every predicate proof" to "one bridge proof," which is worth it only when many predicate proofs amortise that one bridge. And an attestor-signed mirror with **no** ZK on top is strictly worse than A (you pay for a mirror and still reveal/trust as in L0), so B is only interesting *with* the ZK layer.

What B actually buys over A is real and worth naming: it moves predicate computation from the attestor to the **prover**, so a person can prove *arbitrary* graph predicates the attestor never pre-computed, and reveal only the answer — self-service, zero-knowledge graph queries over attestor-vouched data. That is the genuine capability a Poseidon mirror unlocks.

## 3. Why defer (the reasoning)

1. **No demand.** §9-a is already settled — L0 now — and there is no paying data-market use case at all, let alone one that needs *trustless* or *self-service* graph predicates. A Poseidon mirror is a large, speculative investment against a hypothetical consumer.
2. **It is invasive to a substrate.** A mirror means every record/edge is *also* committed under Poseidon: a second Merkle structure to build, store, and keep in sync, a new hash primitive (Poseidon over the right field) added to `protocol-types`, and — for C — the bridge machinery. It also **forks the commitment story** (SHA-256 `recordHash` for attestation, Poseidon for ZK), which is precisely the "two encodings to disagree about" this codebase designs against. That surface is not worth adding on spec.
3. **A/B already covers the market's real asks.** L0 (attestor predicates, shipped) answers "prove ≥3 generations" or "descends from cohort X" today; L1 (self-proof, #2015) answers numeric predicates trustlessly. The only gap a mirror fills is *self-service, zero-knowledge graph* predicates — which no one is asking to pay for.
4. **Don't hand-roll it.** L1 (#2015) is deliberately marked `experimental-unaudited` because hand-rolled ZK cannot be trusted without external review. A Poseidon mirror + SNARK circuits is far more, and far more dangerous, hand-rolled crypto. If it is ever built it must ride a **vetted ZK stack** and a cryptographer — which is another reason not to start speculatively.

## 4. What we do instead, now

- **Graph predicates → L0.** FamilySearch signs `descends-from:<cohort>`, `within-meioses:<n>:<cohort>`, `ancestry-region:<r>>=<k>` as `kin.predicate` attestations (already built). Trusted, shipping, and it is the trust the market already extends to FamilySearch's data.
- **Numeric predicates → L1** (self-proof, #2015, experimental).
- Nothing new is built for L2.

## 5. Triggers that flip this decision

Build **B (attestor-signed mirror + ZK)** when *all* hold:
1. a concrete, paying use case needs provers to prove **arbitrary or high-volume** graph predicates the attestor will not pre-compute per query;
2. **attestor-fidelity trust is acceptable** (it usually is — you already trust FamilySearch's tree); and
3. predicate volume is high enough to amortise the mirror's construction.

Escalate to **C (bridge-proven mirror)** only when a use case *specifically cannot* trust the attestor for fidelity — a genuinely trustless data market — and is willing to fund the in-circuit ECDSA/SHA-256 bridge and its audit. Expect this to be rare.

## 6. Design constraints for if/when it is built

- **Adopt, don't invent.** Align with a vetted ZK-identity stack; `bsv-blockchain/identity`'s `zk-proofs-and-poc` is the BRC-42/secp256k1-native reference and already does the SNARK-friendly-commitment move (`bsv-blockchain/identity`). Interop beats a bespoke mirror.
- **The mirror is additive and derived.** The signed `kin.edge` set + `recordHash` stay the identity; the Poseidon tree is a *projection* of them, never a second source of truth.
- **For C, prove the bridge or do not bother.** An attestor-signed mirror dressed up as trustless is a lie; if fidelity is not proven in-circuit, call it B and price the trust honestly.
- **Cryptographer required.** Same standard L1 fell short of; do not repeat it at larger scale.

## 7. Non-goals

- Building any Poseidon commitment, mirror, or SNARK circuit under this decision — it is a *deferral with conditions*, not a design.
- Re-rooting lineage off ECDSA/SHA-256 (§ the identity is the signed edges + `recordHash`).
- Presenting an attestor-signed mirror as trustless (option B is L0-fidelity trust with ZK privacy — say so).
