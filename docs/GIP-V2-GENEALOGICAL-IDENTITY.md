# Genealogical Identity Protocol v2 — kinship as signed edges, not GEDCOM

**Status:** design note (kinship code lands in a following slice; the edge substrate exists today)
**Modernizes:** the original **Genealogical Identity Protocol (GIP)** (D. Robles / GitBook, Nov 2024) — GEDCOM-as-identity, "Proof of Ancestor" via Longest Common Substring, field-indexed key derivation
**Builds on:** the composable identity substrate in this kit — `src/associations/` (the edge substrate), `src/social/` (kinship + sibling leaves), `src/zk/` (predicate proofs), and page-0 / `did:bsv` identity recovered as a service.

---

## 0. One-liner

The original GIP made **genealogy the key material** and **a GEDCOM file the identity**. v2 keeps the vision — lineage as a decentralized, self-sovereign, cryptographically-verifiable backbone — and moves it onto two layers that already run here: **Plexus** gives each person a recoverable identity key universe (a page-0 root), and **Semantos** composes their genealogy as a set of mutually-signed kinship *edges* over those keys, to their relatives' roots. An attestor such as **FamilySearch is a high-weight co-signer on those edges, not the source of truth.** GEDCOM demotes from *substrate* to *import/export*.

> *"We compose identity, and it exists as our edges with peers."* Genealogy is the oldest such graph. It was always edges; GEDCOM is just one file format that flattened them.

## 1. What the original GIP is (a fair summary)

The 2024 GIP is a genuinely visionary document and this note is a modernization, not a repudiation. Its load-bearing ideas:

- **GEDCOM as the identity dossier** — each person's GEDCOM file is their "K-Asset" (Knowledge Asset, per Robles' Innovation Bank), a unique identity marker.
- **Field-indexed key derivation** — every identity field gets a hierarchical numeric index (`1.4 dateOfBirth`, `2.2.3 motherMaidenName`, `8.1.2 secretAnswer`); a key is derived from a chosen subset: `combinedHash = H(v₁)‖H(v₂)‖H(v₃)` → KDF. A **derivation tag** (`[1.4, 2.2.3, 8.1.2]`) is stored off-chain so keys can be recovered by re-entering the data. Double-hashing (`H(H(value))`) stored for verification-without-exposure.
- **Proof of Ancestor** — verify "the longest unbroken chain of ancestors" across GEDCOM versions using **Longest Common Substring (LCS)** over the files.
- **Child→parent→child signing** — a child signs their GEDCOM and sends it to a parent; the parent integrates the child's hash, signs, sends it back; the child re-versions incorporating the parent's signed hash. Replicated up the generations → an authenticated tree. Hash-based dependencies modelled as *dynamic edges* (a GEDCOM's hash evolves as relatives complete theirs).
- **Selective disclosure** — context-scoped signing identities; merkle proofs of field subsets; "100 points of ID" / ZK-of-age.
- **P2P transaction model** — contact books of verified peers; end-to-end auth; small-world miner network for double-spend.
- **Standards / compliance** — SSI, ISO/IEC 29115, GDPR (data minimization, erasure).

## 2. The two things v2 changes — and exactly why

### 2.1 The brainwallet flaw (fatal in a *public genealogical* protocol)

The original derives your master key from `H(dateOfBirth)‖H(motherMaidenName)‖H(secretAnswer)` etc. **This is a brainwallet** — a key whose entropy is your personal facts. In a genealogical protocol it is self-defeating, because:

- `motherMaidenName` and `dateOfBirth` are the **canonical low-entropy security-question anti-patterns**; `placeOfBirth`, parents' names, sibling names are all *public genealogical record* — which is the entire point of a shared genealogical graph.
- So the very data the protocol makes *verifiable and shared* is the data the key is derived *from*. An attacker who can read your tree — the protocol's success condition — can **reconstruct your key**. Entropy that is published cannot also be a secret.

This repo already hit — and then **hardened** — the weaker form of this: an early challenge-derivation *salted only by email*. The distinction that matters is not "derived vs random" — it is **what you derive from**:

- **Never from public data.** `dateOfBirth`, `motherMaidenName`, `placeOfBirth`, parents' and siblings' names are the shared genealogical record itself. Deriving a key from them is self-defeating — the tree *is* the key. That door stays shut, permanently.
- **Private challenge answers under a server-held salt are the model.** The root derives from user-set challenge answers stretched with **Argon2id under a server-held salt** (`deriveRootKeySecure`), OTP-gated, established by registering with Plexus and enrolled for **recovery-as-a-service**. Neither the public tree nor the answers alone reconstruct it: an offline attacker with the answers still lacks the salt; the operator holding the salt never sees the answers. That two-factor split is exactly what the naive email-salt version lacked.
- **Local self-custody alternative.** Instead of server-side derivation, a wallet can seal a compatible **challenge-gated recovery envelope** — a high-entropy root wrapped under an answers-KEK (the answers-KEK *wraps* the root; it is not the root) — and enroll *that* for the same service (the recovery-envelope design).
- Either way, genealogical facts become **attested edges and disclosed fields** — signed *by* the key, never the material the key is derived *from*.

**v2 rule:** your *public genealogy* is never key material. Identity is anchored to private challenge answers + a server-held salt (or a self-custodied envelope), and recovered as a service — never from data that lives in the tree.

### 2.2 GEDCOM-as-substrate + LCS "proof" (fragile; the user's explicit ask)

- **GEDCOM** is a 1984 LDS flat-file format. Making it *the identity* couples identity to a brittle text encoding, and "Proof of Ancestor via **Longest Common Substring** across GEDCOM versions" is a **string-similarity heuristic, not a cryptographic proof** — it is sensitive to formatting, reordering, transliteration, and non-ASCII names, and proves textual overlap rather than a signed relationship.
- **v2:** a kinship relationship is a **signed edge between two page-0 keys**. "Proof of Ancestor" becomes a **verifiable path of mutually-signed kinship edges** (§6) — a chain of BRC-42 signatures, not a substring match. GEDCOM survives only as an **import/export codec** (§8): read a GEDCOM to *bootstrap* edges, write one to *interoperate* with legacy tools. The identity does not live in it.

The one original idea that is *cryptographically sound and worth keeping verbatim* is the **child→parent→child signing scheme** (§1). v2 does not discard it — it recognizes it as exactly a pair of `signAssociation` vouches (§5), and drops only the GEDCOM re-versioning wrapper around it.

## 3. The v2 model — a Plexus root plus a Semantos edge graph

```
                       (FamilySearch certifier key)
                                  │ co-signs high-weight edges
                                  ▼
   page-0(you) ──kinship:parent──▶ page-0(mother)      each edge = an Association:
        │  ▲                          │                  { kind: 'kin.edge',
        │  └──kinship:child───────────┘                    display: '<relation>|<counterpart page-0>',
        │                                                   vouchedBy: <asserter page-0>,
        ├──social.github────▶ (proof-of-human leaves,        signature: sign(subject, kind, display) }
        ├──social.google───▶  §humanityEvidence)
        └──body.membership─▶ (professional edges)
```

- **The root (Plexus)** is page-0 (`did:bsv:<page-0-pubkey>` when an external verifier needs an addressable identifier — the wrapper already exists, `did-bsv.ts`, brain resolver `GET /api/v1/did`). The identity key universe — root, tier-0, page-0, org nodes, recovery — is the Plexus layer (§1).
- **An edge (Semantos)** is an `Association` (`associations/index.ts`): `{kind, display, vouchedBy, signature}`, committed into a merkle root over the L8 field-tree, disclosed one leaf at a time with a proof. The Semantos graph is built over the Plexus keys. **Kinship is one `kind` (`kin.edge`) among many** — sitting beside the OAuth proof-of-human leaves (`social.github/google/facebook/x`), professional-body memberships, ORCID, licences.
- **No new machinery.** The genealogical protocol is a **new edge namespace on an existing substrate**, plus an import/export codec and an attestor integration. That is the whole point of "identity = edges": genealogy was always a graph.

## 4. Every GIP concept → an existing Plexus/Semantos primitive

| Original GIP | v2 mechanism | Status |
|---|---|---|
| GEDCOM file = identity dossier | page-0 root + edge set; record payload in a neutral format (Markdown → GEDCOM X), GEDCOM via mapping (§8) | root/edges built; codec TODO |
| Field-indexed **brainwallet** key derivation (from *public* genealogy) | root from **private challenge answers + server-held salt** (Argon2id), or a self-custodied envelope; public genealogy never key material (§2.1) | built (`deriveRootKeySecure` / recovery envelope) |
| Derivation tag → deterministic recovery | **recovery-as-a-service** (challenge answers + server salt), or a self-custodied answers-KEK envelope | built (the recovery-envelope design) |
| Double-hash "verify without exposure" | **merkle field disclosure** (L8 `field-tree`): verifier sees sibling hashes | built |
| **Proof of Ancestor** (LCS over GEDCOM) | **path of mutually-signed kinship edges** (§6) | design (this note) |
| **Child→parent→child signing** | a kinship **bond** = two `signAssociation` vouches (A→B, B→A) (§5) | substrate built; `kin.edge` kind landed |
| Hash-based dependencies as dynamic edges | edges are first-class; versioning by re-signing an edge, not re-hashing a file | built (edges) |
| Selective disclosure / "100 points of ID" | `discloseAssociation` + `readDisclosedAssociation`; per-edge provenance survives | built |
| Attestation by relatives / cross-verify vs external DBs | `vouchedBy` per edge; **FamilySearch as certifier** (§7) | design (this note) |
| Contact books of verified peers | contact-book + edge set | built |
| SSI / DID interop | `did:bsv` over page-0 | built (#1989/#1991) |
| Proof of human / personhood | **`humanityEvidence`** — breadth of social leaves (§ sibling) | built (#1992) |
| Data markets for anonymized lineage | disclose *proofs of predicates* over the edge set, not the records | future (predicate proofs) |

The striking result: **most of GIP v2 is already built.** What is genuinely new is (a) the `kin.edge` semantics + bond, (b) the ancestor-path proof, (c) the FamilySearch attestor integration, (d) the record codec (Markdown ↔ GEDCOM X ↔ legacy GEDCOM / XHTML).

## 5. The kinship edge — claim vs bond (the child→parent→child scheme, precisely)

A **kinship claim** is a single directed, signed edge:

```
kind      = ASSOCIATION_KINDS.kinship            // 'kin.edge'
display   = "<relation>|<counterpart-page0-pubkey>"   // e.g. "parent|02a4…"  relation ∈ {parent,child,sibling,spouse,…}
vouchedBy = <asserter page-0 pubkey>
signature = signAssociation(asserterSk, subjectPage0, kind, display)   // subject bound → not a bearer token
```

Because `vouchPreimage` binds the **subject key**, a signed kinship leaf cannot be lifted into a third party's set — the same property that protects every association here. A **self-asserted** claim ("this is my mother") needs no special case: `vouchedBy` is your own page-0, and a reader weighs it as a self-claim.

A **kinship bond** is the pair present in *both* directions:

- A→B: *A* signs "parent | B" bound to subject A (A asserts B is A's parent), and
- B→A: *B* signs "child | A" bound to subject B (B asserts A is B's child).

**This pair IS the GIP's child→parent→child signing scheme** — mutual, symmetric, each endpoint holding a key and vouching — expressed as two `signAssociation` calls instead of a GEDCOM round-trip. A *bond* (both edges) is strictly stronger evidence than a *claim* (one edge): a single edge is one person's word; a bond is two people who each control their root agreeing on the relationship. Verifier policy decides how much a claim vs a bond is worth — the substrate records both faithfully and does not collapse them.

Consistency (A says "parent", B must say "child", not "sibling") is a **verifier-side** check over the disclosed pair, deliberately not enforced at signing time — the substrate stores attestations; a resolver interprets them (the same principle as `stake` having no built-in tally: interpretation is policy, not substrate).

## 6. Proof of Ancestor v2 — a path, not a substring

To prove "X descends from Y across *n* generations," present the **path of kinship edges** X → p₁ → p₂ → … → Y, each edge a claim or (stronger) a bond, and let the verifier walk it:

1. Each hop verifies as an ECDSA signature over `vouchPreimage(subject, 'kin.edge', "<relation>|<next>")` — a real cryptographic check, replacing LCS entirely.
2. Each hop optionally carries a **FamilySearch co-vouch** (§7), raising that hop's weight.
3. The "longest unbroken chain of ancestors" the original prized becomes the **longest path of consistent, signed hops** — and *unbroken* now means *cryptographically continuous* (each subject is the next edge's counterpart), not *textually similar*.

Selective disclosure still holds: you disclose the *edges on the path* (with proofs to your committed root), not your whole tree. The leaf-count leak noted in `associations/index.ts` applies — a path reveals roughly how many relatives sit around each node; hiding that needs fixed-width padding, a schema decision, out of scope here but worth stating explicitly.

## 7. FamilySearch as attestor — a precise, valuable role

FamilySearch holds one of the world's largest genealogical trees. Its role in v2 is **certifier / high-weight voucher**, never *owner of your identity*:

- **What it signs:** a FamilySearch **signing node** co-signs a kinship edge (or a whole disclosed subtree's root) as an `Association` — attesting *"this parent→child relationship matches an authoritative FamilySearch record"* (optionally citing a record id in `display`). The edge's `vouchedBy` is a **delegated node key**, not the trusted anchor itself (see *Key hygiene* below). This is exactly the GIP's own "**Cross-Verification** against external genealogical databases" (original §Data Accuracy), made a first-class signed edge.
- **What it does NOT do:** it does not hold a user's root, does not custody a tree, and cannot forge a bond nobody signed — its co-vouch raises an edge's *weight*, it does not *create* the edge. A person can hold FamilySearch-attested edges and Semantos-only edges side by side; a verifier weighs them differently and sees *who* vouched each (per-edge provenance is preserved by design).
- **Key hygiene — the anchor never signs (`delegateSigner` / `delegatedVouchTier`):** the key a verifier trusts (FamilySearch's root / org identity — the *anchor*) does not sign vouches. It signs a short **delegation** authorizing a signing *node*; the node signs the vouches; a verifier that trusts only the anchor accepts a node's vouch because a valid delegation chains it back. One key never does both — rotation is a new delegation, multiple signing desks are multiple delegations under one anchor, and the trust set stays a single root. Because the production node key (`deriveOrgNodeSk`) is a *keyed* (deliberately unlinkable) child of the org's tier-0, the relationship can't be derived from public keys — it is proven by that signed delegation (the role the wallet's `OrgBindingRecord` plays), not a derivation check. `bun delegation-demo.ts` runs the whole model against real signatures.
- **An off-server certifier:** the certifier (`cli.ts` in this kit) runs off-server — the signing key never reaches a server — with the Holder/Voucher/Certifier split: the Holder assembles the set locally, a Voucher signs one edge, the Certifier signs a *root* and sees nothing inside. FamilySearch slots in as a Voucher (per-edge) and/or Certifier (root witness) with no new trust machinery.
- **What the role gives an attestor:** it lends authority to user-held, self-sovereign identities **without** becoming an identity provider, a custodian, or a KYC liability. The attestor signs facts it already holds; users carry the proof; the attestor stores no keys and takes on no account-recovery burden. Its data becomes *verifiable attestations* rather than a walled database — the original's "K-Asset" idea, without the GEDCOM lock-in.
- **Monetising the role (optional):** an attestor can charge to *issue* attestations over x402 — signing with a **delegated node under its Plexus org anchor** (the anchor stays in the vault, a scoped rotatable node signs at the portal), delivered by a real-time portal with an async fallback — while **verification stays free and offline**. See [`GIP-V2-PAID-ATTESTATION.md`](GIP-V2-PAID-ATTESTATION.md).

## 8. The record payload — a neutral format, GEDCOM via a mapping library

The signed `kin.edge` layer is the identity. The *biographical record* that rides alongside it — names, dates, places, sources — deliberately does **not** live in GEDCOM. GEDCOM 5.5.1 is a 1984 flat-file format; making it the native store repeats the original's coupling to a brittle encoding. Instead, three layers, each doing the one thing it is good at:

- **Author / store — Markdown + JSON frontmatter.** The human-facing, git-diffable native format: a person's record reads as a document, corrections are legible line by line, and the GIP's "adaptive versioning" becomes ordinary version history rather than re-hashed files. This is what a person writes and reads. (JSON, not YAML — the substrate carries no YAML dependency, and it stays Unicode-safe.)
- **Interchange / attest — GEDCOM X JSON.** The mapping library canonicalizes the record to **GEDCOM X** — FamilySearch's *own* modern successor to GEDCOM (a JSON/XML conceptual model, not the flat format). This canonical form is what an edge's optional `record-hash` commits to, and what FamilySearch co-signs (§7). Machine rigor lives here, on export — so the authoring format need not carry it.
- **Display / legacy — XHTML and GEDCOM 5.5.1.** The same library renders a record to XHTML (a browser-viewable, embeddable verifiable page, pairing with `did:bsv`) and maps to/from legacy **GEDCOM 5.5.1 / 7.0** so classic tools still interoperate. Both are *views*: signatures and page-0 keys have no GEDCOM representation, so a GEDCOM export is lossy by design.

Import bootstraps edges: parsing any of these — a legacy GEDCOM, a GEDCOM X file, a Markdown record — yields *self-asserted* `kin.edge` claims (the importer knows only what the file says and cannot forge the counterpart's signature), which relatives then counter-sign into bonds (§5).

**No LCS, no versioned-file hashing, no record-derived keys.** The record is data in and data out; the identity is the signed edges over it.

## 9. Privacy, disclosure, and "data markets"

- **Selective disclosure** is already the substrate's core behavior (`discloseAssociation`/`readDisclosedAssociation`), so the GIP's field-subset merkle proofs come for free.
- **GDPR erasure** is cleaner than the original: there is no immutable on-chain GEDCOM to contradict "right to erasure." Edges live in the holder's set and the counterpart's set; a person deletes their half, and a bond degrades to a one-sided claim. (A counterpart's independently-held claim about you is their record, not yours — a real-world nuance to document, not a bug.)
- **The GIP's "secondary data markets for anonymized lineage"** map to **predicate proofs over the edge set** (prove "≥3 generations of verified Scottish ancestry" without revealing names) — a future extension, and the honest place to note it is *future*: the substrate discloses signed leaves today, not zero-knowledge predicates over them. `bsv-blockchain/identity`'s per-RP ZK pseudonyms are the reference design if that becomes a goal (`bsv-blockchain/identity`).

## 10. What is already built vs new (so the surface is small)

**Already built (this repo):** page-0 root + recovery envelope; the `Association` edge substrate with per-edge signed provenance and merkle selective disclosure; `ASSOCIATION_KINDS.kinship` (landed with #1992); off-server certifier (boomspace); `did:bsv` interop; `humanityEvidence` proof-of-human leaves; contact books.

**New for GIP v2:** (a) `social/kinship.ts` — `kinClaim`, `kinBond`, path-verification helpers over `kin.edge`; (b) a record codec — Markdown+frontmatter authoring, canonicalized to GEDCOM X JSON for interchange/attestation, mapping to/from legacy GEDCOM 5.5.1 and an XHTML render; (c) the FamilySearch certifier integration (a boomspace strategy + a well-known FamilySearch certifier key); (d) — later — predicate proofs for anonymized lineage markets.

## 11. Load-bearing decisions

1. **Public genealogy is never key material.** The root derives from *private* challenge answers under a server-held salt (not tree data), or a self-custodied envelope; facts are disclosed/attested, not derived-from. Reverses the original's central mechanism; non-negotiable (§2.1).
2. **A relationship is a signed edge, not a file diff.** Cryptographic path proof replaces LCS (§6).
3. **A bond is two vouches, a claim is one** — and the substrate keeps them distinct; weighting is verifier policy (§5).
4. **FamilySearch attests, it does not custody.** Certifier/voucher, off-server key, per-edge provenance preserved (§7).
5. **The record payload is a neutral format** — Markdown authoring → GEDCOM X JSON interchange; GEDCOM 5.5.1 is a mapping target, never the substrate (§8).
6. **Interpretation lives in the resolver, not the substrate.** Consistency/weighting/policy are read-side, matching the repo's stake/association discipline (§5).

## 12. Non-goals

- Re-deriving keys from personal data in any form (the original's core; foreclosed by §2.1).
- Making GEDCOM canonical, or LCS a proof.
- FamilySearch (or anyone) holding user roots or becoming an IdP/custodian.
- On-chain immutable family records (defeats GDPR erasure; edges are holder-held).
- ZK predicate/data-market proofs *in this note* — named as future, not specified here.

## 13. In one paragraph

A person holds a self-sovereign root — a Plexus key universe, recoverable via their own challenge answers (as a service, or self-custodied) — and assembles their lineage as Semantos edges signed to their relatives' roots. An attestor such as FamilySearch **co-signs the edges it can vouch for**, lending its authority to a relationship without holding anyone's keys, custodying anyone's account, or taking on KYC or recovery liability: users carry the proofs, the attestor stores none. Genealogy stops being a file format people export and becomes a graph people *prove* — with the attestor as a trusted signer on it, not a database people are locked into.
