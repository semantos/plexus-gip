# FamilySearch integration seam — what FS exposes, and the adapter to it

**Status:** research + design note (no code) — decisions in §6
**Answers:** "does the design anticipate FamilySearch's seams, or expect FS to conform to ours?"
**Builds on:** `social/providers.ts` (OIDC leaves) · `linkedin-verify.ts` (id_token verify) · `social/record.ts` + `gedcom.ts` (GEDCOM X ↔ recordHash) · `social/familysearch.ts` (attestations) · the payments module (the fiat-attestation shape)
**Relates to:** [`GIP-V2-GENEALOGICAL-IDENTITY.md`](GIP-V2-GENEALOGICAL-IDENTITY.md) §7, [`GIP-V2-PAID-ATTESTATION.md`](GIP-V2-PAID-ATTESTATION.md)

> Sourced from the public FamilySearch developer docs (Sept 2026); items marked **⚠ confirm** need a real app key + FamilySearch Developer Support to pin down, because they are not fully specified publicly.

---

## 0. The answer

Today's design mostly **expects FamilySearch to conform to our interfaces** (sign our BRC-42 preimages with a key in our org-derivation scheme). That is the wrong thing to ask first. FamilySearch exposes real, well-shaped seams, and the near-term integration should **adapt to them**, not require FS to build toward us:

- **Identity** — use FamilySearch's **OpenID Connect**. An FS login already yields a *signed* id_token; it drops straight into our OIDC-leaf machinery. **Zero FS build.**
- **Tree data** — read the **Family Tree API** (GEDCOM X). It returns *unsigned* JSON, so a **bridge re-attests** what it read (the same "fiat rail publishes nothing checkable" shape our payments layer already models).
- **Data model** — already aligned: FS's canonical model **is GEDCOM X**, which our record codec already emits and hashes.

"FamilySearch runs its own org key and signs our attestations" (the [paid-attestation](GIP-V2-PAID-ATTESTATION.md) `IssueSigner`) is the **high-assurance upgrade**, not the entry ticket. The one thing we genuinely need *from* FS is **API access under their partner terms** — a business/legal seam, not an engineering-conformance one.

## 1. What FamilySearch actually exposes

**OAuth 2.0 + OpenID Connect.** Grant types: Authorization Code (RFC 6749 §4.1), Client Credentials (restricted, service accounts, approval required), Unauthenticated (a handful of read APIs only), and **OpenID Connect** (`scope=openid`). Token endpoint `POST /cis-web/oauth2/v3/token`; it returns `access_token`, `refresh_token`, and — with `openid` — a signed **`id_token`** carrying identity claims (`user_id`, `given_name`, `family_name`, `email`, `locale`, `gender`, `country`, `qualifies_for_affiliate_account`). A "OAuth 2.0 for Native Apps" guide exists (**⚠ confirm PKCE**). Access is **per-approved-app (all-or-nothing), not granular scopes** for tree data. **⚠ confirm**: token lifetime/refresh, and the OIDC **JWKS/discovery** endpoint (not in the public docs — needed to verify id_tokens the way `linkedin-verify.ts` does).

**Family Tree API (GEDCOM X).** `GET /platform/tree/persons/{pid}`, `…/{pid}/parents`, `…/{pid}/spouses`; relationships modelled as **ParentChild** and **Couple**. Apps are classified **read-compatible** vs **write-compatible**; access requires **partner status + a signed addendum**, and write additionally requires certification against FamilySearch's API-compatibility checklists. (We only need **read**.)

**Data model — GEDCOM X.** FamilySearch created GEDCOM X; the API serves it. Top-level types Person, Relationship, SourceDescription, Conclusion, plus **attribution** metadata (contributor id, timestamps, change history).

**Cryptography — asymmetric between the two surfaces.** The Family Tree API returns **plain JSON over TLS with no detached signature** — a third party cannot verify a tree fact without calling FamilySearch itself. But an **OIDC `id_token` is a signed JWT** — verifiable against FS's keys. So *identity is verifiable; tree data is not.* FamilySearch holds **no keys in our BRC-42/secp256k1 scheme** and signs none of our preimages.

## 2. The load-bearing split

| Surface | What FS returns | Verifiable by a third party? | Consequence |
|---|---|---|---|
| **Identity** (who this FS account is) | signed OIDC `id_token` (JWT) | **Yes** — verify against FS's keys | drop into our OIDC-leaf path directly |
| **Tree data** (kinship facts, records) | GEDCOM X JSON over TLS | **No** — must trust the caller/FS | needs a bridge that re-attests (notary) |

This is exactly the distinction our own `payments/` layer draws between a `PaymentVerifier` (checks a chain — verifiable) and a fiat `PaymentAttestor` (a rail "publishes nothing a third party can check unaided"). FamilySearch's tree data is fiat-rail-shaped; its identity is chain-shaped.

## 3. The adapter, layer by layer

### Identity — FamilySearch as an OIDC leaf (meets their seam, zero FS build)

Add `familysearch` to `social/providers.ts` as an OIDC provider (issuer + discovery + the identity claims above), verified exactly like `linkedin-verify.ts` verifies an id_token against a JWKS. An FS login then becomes a signed social-attestation **leaf** binding an FS account (its stable `user_id`) to a page-0 key — `subjectType: 'global'` (the `user_id` is durable and correlatable, so no audience-scoping, matching our Google/GitHub handling). This is a first, small, *entirely-FS-native* integration: nothing new for FamilySearch to build. **⚠ confirm** the JWKS/discovery URL to wire the verify.

### Tree data — a bridge re-attests the read (the fiat-rail shape)

Because the Tree API is unsigned, three options, by how much FS must build and how much trust the verifier extends:

1. **FS-as-signer (upgrade, most FS build).** FS runs an org key ([`deriveOrgNodeSk`](GIP-V2-GENEALOGICAL-IDENTITY.md)) and signs our attestations directly — the strongest story (their own key vouches; verifiers trust their root). FS has no such infra today (their platform is OAuth+REST), so this is a later upgrade, not the start.
2. **Bridge / notary (recommended near-term).** An authenticated reader fetches the person's GEDCOM X from the Family Tree API, maps it to our `RecordModel`/`kin.edge`, canonicalizes to `recordHash`, and a **bridge key re-attests** it (`recordAttestation` / `familySearchKinVouch`). Trust = the bridge faithfully relayed what FS's API returned. To bound that trust: **pin the fetch to the subject's own FS OIDC session** — the same login that produced the identity leaf (§3) — so the attestation reads "*the FS account that OIDC-proved control of page-0 X read this relationship from the Family Tree at time T*", and retain the API response + OAuth context as the receipt. This composes the verifiable identity layer with the unsigned data layer into a meaningful, if not fully trustless, vouch.
3. **User-mediated (least trust machinery).** The user logs in to FS (OIDC → page-0 leaf), pulls their *own* tree, and **self-asserts** the kin edges (`recordToKinClaims`); the FS OIDC leaf corroborates that the self-asserter controls an FS account. No bridge key, weaker vouch (self + "has an FS account with this tree"), zero new trusted party.

### Data model — already aligned

FS GEDCOM X ⇄ our `RecordModel`/`recordHash` is a mapping, not a translation: ParentChild → `parent`/`child` `kin.edge`, Couple → `spouse`, person facts → record facts. `gedcom.ts` already imports GEDCOM-shaped trees; extend it from flat GEDCOM 5.5.1 to **GEDCOM X JSON** from the API. This is the one layer where we already met FamilySearch, by design.

## 4. What we ask FS for vs. what we build

- **From FamilySearch:** **read API access** — partner status + the signed addendum. (No write; no certification-for-write; no new signing infra.) That legal/business seam is the real gating item, not any code.
- **We build:** the FS OIDC provider leaf, the GEDCOM-X→RecordModel mapper, and the bridge re-attestor (which is just an `IssueSigner` implementation behind the [paid-attestation portal](GIP-V2-PAID-ATTESTATION.md)'s existing seam).
- **Optional, later:** FS-as-signer, if/when FamilySearch wants their own key to vouch directly.

## 5. Where this lands in the code we already have

- **`social/providers.ts`** — add the `familysearch` OIDC descriptor; a cartridge-side `familysearch-verify.ts` mirrors `linkedin-verify.ts`.
- **`gedcom.ts`** — a `recordFromGedcomX(json, subject, xrefToPage0)` beside the 5.5.1 importer.
- **The paid-attestation portal's `IssueSigner`** — the bridge/notary is one implementation of it; the portal already gates issuance and handles real-time vs async, so paid FS-backed attestation is the portal + this adapter.
- **`payments/`** — the fiat-attestation vocabulary (finality, receipts) is the right shape for the bridge's evidence trail.

## 6. Decisions

- **(a) DECIDED — adapt first, don't require conformance.** Near-term: FS OIDC leaf (identity) + read-only Tree-API bridge (data). FS-as-signer is the upgrade.
- **(b) DECIDED — read-only.** We never write to the Family Tree; no write-certification needed. Attestation is additive and lives in our graph.
- **(c) OPEN — whose token the bridge uses.** The **subject's own** authorization-code/OIDC session (recommended — consent + provenance are the user's) vs a partner client-credentials service token (simpler, but the bridge acts on its own authority).
- **(d) OPEN, and the real gate — API access.** Partner status + signed addendum under FamilySearch's terms is the dependency to start; everything above is buildable once it exists (a sandbox app key is enough to prototype identity + read).

## 7. Non-goals / caveats

- Not building any of this here — it is the research + design; the FS OIDC leaf is the smallest first slice.
- **⚠ confirm with FamilySearch Developer Support / a real app key:** the OIDC JWKS/discovery endpoint and id_token signing alg, token lifetime + refresh, PKCE for native apps, and the exact read-access addendum terms. This note is sourced from public docs and must be validated against a live integration before code.
- Not writing to FamilySearch, not mirroring their tree, not asking them to adopt BRC-42 to begin.

## Sources

- [FamilySearch — Authentication](https://developers.familysearch.org/main/docs/authentication)
- [FamilySearch — OAuth 2.0 for Native Apps](https://www.familysearch.org/en/developers/docs/guides/oauth2-native-apps)
- [FamilySearch — API Resources](https://www.familysearch.org/developers/docs/api/resources)
- [FamilySearch — Read Parents / Read Spouses of a Person](https://www.familysearch.org/en/developers/docs/api/tree/Read_Parents_of_a_Person_usecase)
- [FamilySearch — User Tree Access Model](https://developers.familysearch.org/main/docs/user-tree-access-model)
- [FamilySearch — GEDCOM X guide](https://www.familysearch.org/developers/docs/guides/gedcom-x) · [GEDCOM X conceptual model](https://github.com/FamilySearch/gedcomx/blob/master/specifications/conceptual-model-specification.md) · [JSON format](https://github.com/FamilySearch/gedcomx/blob/master/specifications/json-format-specification.md)
- [FamilySearch — API Compatible Checklists (partner access)](https://www.familysearch.org/innovate/api-compatible-checklists)
