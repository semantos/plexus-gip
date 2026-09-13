# Genealogical Identity Protocol v2 — Quickstart (try it)

A hands-on companion to the design note ([`design/GIP-V2-GENEALOGICAL-IDENTITY.md`](GIP-V2-GENEALOGICAL-IDENTITY.md)) and the shareable overview kit. Everything below runs against the code on `main` — no external service, no test doubles.

> **What this is — two layers.** **Plexus** gives each person a self-sovereign identity key universe (a recoverable page-0 root); **Semantos** composes their genealogy as **mutually-signed kinship edges** over those keys, to their relatives' roots. An attestor such as FamilySearch co-signs edges and records **without holding anyone's keys**. GEDCOM is import/export only; genealogy is a signed graph.

---

## 1. Prerequisites

- [Bun](https://bun.sh) ≥ 1.3
- A checkout of `semantos-core` with dependencies installed:
  ```bash
  bun install
  ```

## 2. The 60-second demo — the whole protocol in one command

```bash
bun walkthrough.ts
```

It derives demo keys for Alice, her mother Mary, her grandmother, and a FamilySearch certifier, then runs — and prints — every step against **real signatures**:

1. **Roots (Plexus)** — page-0 keys (not derived from public genealogy; recovered via private challenge answers + a server-held salt). Steps 2+ are the Semantos graph built over them.
2. **Kinship claim → bond** — Alice signs `parent→Mary`, Mary signs `child→Alice`; the pair is the GIP's child→parent→child scheme as two vouches.
3. **FamilySearch co-signs** the edge — and `vouchTier` shows it as `certifier` vs a `self`-claim vs a `peer` (trust is the verifier's, local).
4. **Record → `recordHash`** — a biography canonicalised to GEDCOM X.
5. **FamilySearch attests the record hash** — signs a digest, holds no record.
6. **L0 predicate** — FamilySearch signs `gen-depth>=2`; the tree stays hidden.
7. **L1 predicate** — Alice proves `born-before<=1970` *herself*, no attestor (⚠ experimental/unaudited ZK), and a false predicate is shown to be unprovable.
8. **Proof of Ancestor** — a cryptographically continuous path Alice→Mary→Grandma (no substring matching).
9. **Legacy GEDCOM import** — bootstrap edges from a tree; relatives not yet enrolled come back as an "invite" list.

## 3. Be the certifier — the FamilySearch CLI

This is the piece an attestor operates. The certifier key **never leaves the machine**; the commands print a portable signed *leaf* that the person folds into their own set.

```bash
# one-time: create the certifier key (stays local, mode 600)
bun cli.ts keygen

# the public key — this is what a verifier puts in its trusted-certifier set
bun cli.ts pubkey
```

Then, given a person's page-0 public key (and a relative's, or a record hash, or a predicate):

```bash
# co-sign a kinship edge: "this person's parent is <counterpart>"
bun cli.ts fs-vouch-kin      <subjectPubkey> parent <counterpartPubkey>

# attest a whole record by its hash (from recordHash())
bun cli.ts fs-attest-record  <subjectPubkey> <recordHash>

# attest a computed property, revealing nothing of the tree (quote it — >= is a shell redirect)
bun cli.ts fs-attest-predicate <subjectPubkey> 'gen-depth>=3'
```

Each prints a JSON leaf like:

```json
{
  "certifier": "0348dc…",
  "kind": "predicate.attestation",
  "subject": "02d473…",
  "association": { "kind": "kin.predicate", "display": "gen-depth>=3", "vouchedBy": "0348dc…", "signature": "3044…" }
}
```

> Need demo public keys to feed these? The walkthrough (§2) prints Alice's and Mary's, or derive your own with `PrivateKey.fromRandom().toPublicKey().toString()` from `@bsv/sdk`.

## 4. Use it from code

Everything is exported from `./src`:

```ts
import {
  selfKinClaim, kinBondConsistent,        // kinship edges + bonds
  recordHash, recordToMarkdown,           // records → GEDCOM X hash
  familySearchKinVouch, vouchTier, trustedSet,   // attestor + trust weighing
  predicateAttestation, verifyPredicateAttestation,  // L0 predicates
  proveNumericPredicate, verifyNumericPredicate, L1_ZK_STATUS, // L1 self-proof (experimental)
  recordFromGedcomTree, recordToKinClaims, // legacy GEDCOM bootstrap
} from './src';
```

The walkthrough script (§2) is the worked example for every one of these.

## 5. What is real, and what is experimental

| Piece | Status |
|---|---|
| Kinship edges/bonds, ancestor paths | production-shaped, tested |
| Record codec (GEDCOM X, `recordHash`), legacy GEDCOM import | production-shaped, tested |
| FamilySearch attestor (record/kinship/predicate) + CLI | production-shaped, tested |
| **L1 numeric self-proof** (`zk/range-proof`) | **⚠ EXPERIMENTAL — hand-rolled, UNAUDITED ZK; `L1_ZK_STATUS === 'experimental-unaudited'`. Needs a cryptographer's review before production.** |
| L2 general graph ZK | not built — deferred by decision ([`design/GIP-V2-POSEIDON-MIRROR-DECISION.md`](GIP-V2-POSEIDON-MIRROR-DECISION.md)) |

## 6. Where to go next

- **Why it's built this way:** [`design/GIP-V2-GENEALOGICAL-IDENTITY.md`](GIP-V2-GENEALOGICAL-IDENTITY.md) (and why the original GIP's brainwallet + GEDCOM-as-identity are gone).
- **FamilySearch's precise role** — attestor, not custodian: §7 of that note.
- **Predicate proofs, the full ladder:** [`design/GIP-V2-PREDICATE-PROOFS.md`](GIP-V2-PREDICATE-PROOFS.md).
