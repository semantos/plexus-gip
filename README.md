# Genealogical Identity Protocol v2 — runnable kit

A **self-contained** slice of the Genealogical Identity Protocol v2, carved from
semantos-core so you can run it without the rest of the monorepo. Its only
dependency is `@bsv/sdk` (the BSV TypeScript SDK, from npm).

> **The idea — two layers.** **Plexus** gives each person a self-sovereign identity
> key universe: a recoverable `page-0` secp256k1 root. **Semantos** composes their
> genealogy as **mutually-signed kinship edges** over those keys, to their relatives'
> roots. An attestor such as FamilySearch co-signs edges, records, and computed
> properties — lending its authority **without holding anyone's keys or accounts**.
> GEDCOM is import/export only; genealogy is a signed graph. The original protocol's
> brainwallet (keys derived from *public* genealogy) and GEDCOM-as-identity are gone.

## Run it

```bash
# 1. install the one dependency
bun install          # (or: npm install)

# 2. watch the whole protocol run against real signatures
bun walkthrough.ts
```

The walkthrough derives demo keys for Alice, her mother Mary, her grandmother,
and a FamilySearch certifier, then prints every step: roots → kinship claim +
bond → FamilySearch co-sign + trust weighing → record + `recordHash` → record
attestation → **L0 predicate** (certifier-signed) → **L1 predicate** (self-proven,
experimental) → Proof-of-Ancestor path → legacy GEDCOM import.

## Be the certifier — the FamilySearch CLI

The certifier key never leaves your machine; each command prints a portable
signed *leaf* the holder folds into their own set.

```bash
bun cli.ts keygen                 # create the certifier key (local, mode 600)
bun cli.ts pubkey                 # its public key — goes in a verifier's trusted set

bun cli.ts fs-vouch-kin        <subjectPubkey> parent <counterpartPubkey>
bun cli.ts fs-attest-record    <subjectPubkey> <recordHash>
bun cli.ts fs-attest-predicate <subjectPubkey> 'gen-depth>=3'   # quote it — >= is a shell redirect
```

Need demo public keys to feed these? `bun walkthrough.ts` prints Alice's and
Mary's, or make your own:
`bun -e "import {PrivateKey} from '@bsv/sdk'; console.log(PrivateKey.fromRandom().toPublicKey().toString())"`.

## Delegated co-vouch — the anchor never signs

FamilySearch shouldn't co-vouch with the same key a verifier trusts (one key doing
both). Instead the trusted **anchor** (its root/org identity) signs a short
*delegation* authorizing a **signing node**; the node signs the vouches; a verifier
that trusts only the anchor still reads a node's vouch as `certifier`, because the
delegation chains it back. Rotation = a new delegation; the trust set stays one root.

```bash
bun delegation-demo.ts   # anchor delegates → node signs → verify; rotation + a forged delegation
```

Because the production node key (`deriveOrgNodeSk`) is a *keyed* child of the org's
tier-0 (deliberately unlinkable), the relationship can't be derived from public keys
— so it's proven by a **signed delegation**, not a derivation check.

## Any body as attestor (`src/bodies/`)

A school, club, scout group, parish, sports club, employer or professional body
confirms one fact about a member from its own records (`member`,
`guardian_of_member`, `age_over_13/16/18` or `helper`) and signs a W3C VC 2.0
credential, an ES256K JWT, about a did:key the member's wallet made for one
platform only. No name, birthdate or record number goes in it. The platform
checks it offline: the holder's answer to its challenge, the body's entry in a
steward-signed registry, the node's delegation from the body's anchor, and the
body's withdrawal list. See [`docs/GIP-V2-BODY-ATTESTATION.md`](docs/GIP-V2-BODY-ATTESTATION.md).

```bash
bun bodies/demo.ts   # a school, then a scout group, through the same code
bun test             # every refusal, the known-answer file, the ported wire formats
```

## Paid-attestation portal (prototype)

FamilySearch can **charge to issue** an attestation over an x402-style `402`
handshake — signing with a **delegated node** under its org anchor (per the
delegated model above: the anchor never signs, and the portal hands out the anchor
+ delegation so a verifier trusts the anchor). Delivered in real time with an async
fallback; verification stays free. See
[`docs/GIP-V2-PAID-ATTESTATION.md`](docs/GIP-V2-PAID-ATTESTATION.md).

```bash
# watch the whole flow (402 → pay → issue), all five paths, against real signatures
bun portal/demo.ts

# or run it as an HTTP service and curl the handshake
bun portal/server.ts
#   POST /attest {subject,claim} → 402 invoice
#   POST /dev/settle {invoiceNonce}   (dev shim — no real chain here)
#   POST /redeem {invoiceNonce}   → { anchor, delegation, leaf }
```

⚠ Prototype: settlement is **mocked**, state is in-memory, no auth. The real
`@semantos/x402` verifier and a real `deriveOrgNodeSk` node key (delegated by the
FS anchor) drop in behind the same ports without changing the portal logic.

## FamilySearch integration (adapter to their real seams)

The adapter meets FamilySearch where they already are — no BRC-42 for them to adopt. See [`docs/GIP-V2-FS-INTEGRATION-SEAM.md`](docs/GIP-V2-FS-INTEGRATION-SEAM.md).

- **Identity — OpenID Connect.** `familysearch` is a social provider (`src/social/providers.ts`); `familysearch/verify.ts` verifies an FS id_token against their JWKS (issuer/keys confirmed live). An FS login binds an FS account to a page-0 key. Zero FS build.
- **Tree data — the bridge.** FamilySearch's Family Tree API serves **unsigned** GEDCOM X, so the bridge reads it and **re-attests** (a notary), pinned to the subject's OIDC session:

```bash
bun familysearch/demo.ts    # read a (mock) FS tree → map GEDCOM X → re-attest, verify
```

⚠ The tree read is mocked (`familysearch/tree-api.ts`). The real client — an authenticated `GET /platform/tree/persons/{id}` — drops in behind the port once FamilySearch **API access (partner status + addendum)** lands; that business step is the only thing not runnable here.

## Use it from code

Everything is re-exported from `./src`:

```ts
import {
  selfKinClaim, kinBondConsistent,               // kinship edges + bonds
  recordHash, recordToMarkdown,                  // records → GEDCOM X hash
  familySearchKinVouch, vouchTier, trustedSet,   // attestor + trust weighing
  delegateSigner, delegatedVouchTier,            // anchor delegates a signing node
  predicateAttestation, verifyPredicateAttestation,   // L0 predicates
  proveNumericPredicate, verifyNumericPredicate, L1_ZK_STATUS,  // L1 self-proof
  recordFromGedcomTree, recordToKinClaims,       // legacy GEDCOM bootstrap
} from './src';
```

## What is real, and what is experimental

| Piece | Status |
|---|---|
| Kinship edges/bonds, ancestor paths | production-shaped, tested in-repo |
| Record codec (GEDCOM X, `recordHash`), legacy GEDCOM import | production-shaped, tested in-repo |
| FamilySearch attestor (record/kinship/predicate) + CLI | production-shaped, tested in-repo |
| **L1 numeric self-proof** (`src/zk/`) | **⚠ EXPERIMENTAL — hand-rolled, UNAUDITED zero-knowledge crypto; `L1_ZK_STATUS === 'experimental-unaudited'`. Needs a cryptographer's review before production.** |
| L2 general graph ZK | not built — deferred by decision |

## Read the design

The `docs/` folder carries the "why", not just the "how":

- [`docs/GIP-V2-GENEALOGICAL-IDENTITY.md`](docs/GIP-V2-GENEALOGICAL-IDENTITY.md) — the protocol, and why the original GIP's brainwallet + GEDCOM-as-identity are gone. **§7 is FamilySearch's precise role — attestor, not custodian.**
- [`docs/GIP-V2-PREDICATE-PROOFS.md`](docs/GIP-V2-PREDICATE-PROOFS.md) — the L0/L1/L2 predicate-proof ladder and its cost/trust tradeoffs.
- [`docs/GIP-V2-POSEIDON-MIRROR-DECISION.md`](docs/GIP-V2-POSEIDON-MIRROR-DECISION.md) — why trustless graph ZK (L2) is deferred, and what would flip it.
- [`docs/GIP-V2-PAID-ATTESTATION.md`](docs/GIP-V2-PAID-ATTESTATION.md) — how FamilySearch monetizes issuance over x402 (the `portal/` prototype above).
- [`docs/GIP-V2-FS-INTEGRATION-SEAM.md`](docs/GIP-V2-FS-INTEGRATION-SEAM.md) — what FamilySearch exposes and the adapter to it (the `familysearch/` code).
- [`docs/GIP-V2-QUICKSTART.md`](docs/GIP-V2-QUICKSTART.md) — the in-repo version of this guide.

## What this kit is not

- Not published to npm and not a product — a **demonstration carve** of the
  protocol, for reading and running.
- The `src/` modules are carved copies from semantos-core (the Plexus/Semantos
  monorepo); the kit-specific pieces are this README, the `src/index.ts` barrel,
  `walkthrough.ts`, `cli.ts`, `sign.ts`, `delegation-demo.ts`, the `portal/`
  and `familysearch/` entry points, and `src/bodies/` with `bodies/demo.ts`.
