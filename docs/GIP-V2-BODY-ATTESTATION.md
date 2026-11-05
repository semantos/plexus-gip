# Any body as attestor

**Status:** built in `src/bodies/`, tested in `test/bodies.test.ts`, pinned by
`test/fixtures/bodies_kat.json`; nothing live. 4 November 2026.
**Generalises:** the "School-vouched age credentials" deck (October 2026) and
the FamilySearch attestor already in this kit (`src/social/familysearch.ts`,
`src/social/delegation.ts`).

## 0. One line

A body that already knows its people (a school, scout group, club, parish,
sports club, employer, professional body) confirms **one fact** about a person
**once**, from its own records. The person proves it anywhere after, and nobody
sees a name or a birthdate.

The deck did this for one body (a school) and one fact (`age_over_16`), to keep
under-16s out of platforms. The same mechanism also runs the other way: a
children's world (vedic-math-lab `docs/KIDS-WORLD.md`) lets in only children
a body vouches for, and those children's guardians.

## 1. What is vouched

One boolean claim per credential, so a holder shows one fact at a time:

| Claim | Means | Typical body |
|---|---|---|
| `member` | This person belongs to the body (enrolled, joined) | school, club, scouts |
| `guardian_of_member` | This adult is a guardian of one of the body's members | school, club |
| `age_over_13`, `age_over_16`, `age_over_18` | From a document the body sighted; issued only once true | school, employer |
| `helper` | An adult the body vouches for to work with children (a current clearance) | school, club, scouts, parish |

A body may vouch only the claims its registry entry lists. Nothing else goes in
a credential: no name, birthdate, student or membership number.

## 2. The parts

```
 steward (registry) ── signs ──▶ registry entry: body did:web, anchor key, kind, claims, period ends, withdrawal list
 body root (anchor, Plexus page-0) ── delegateSigner(…, 'body.vouch') ──▶ signing node (hosted)
 signing node ── signs ──▶ vouch (VC 2.0, ES256K JWT) about the holder's key for ONE relationship
                     └──▶ withdrawal list (Bitstring Status List), fetched whole
 holder ── signs the app's one-time challenge ──▶ presentation ──▶ app checks everything offline
```

- **Who counts.** A registry entry (`BodyRegistryEntryCredential`) is signed by
  a steward the verifier trusts. It names the body's `did:web`, its anchor key,
  its kind, the claims it may vouch, the period ends its vouches may expire on,
  and its withdrawal list. A steward cannot register itself: a body vouching
  for itself counts for nothing.
- **Day-to-day signing.** The body's root never signs a vouch. It signs a GIP
  delegation (`delegateSigner(root, node, 'body.vouch')`) to a hosted node, and
  each vouch carries that delegation as `evidence`. This is the deck's "proof
  that a hosted node acts for its school". Replacing the node is a new
  delegation; the verifier's trust stays with the root.
- **Expiry is a period end, never a birthday.** A credential that expired on a
  child's 13th birthday would give the birthdate away, so `validUntil` must be
  one of the entry's published period ends (the end of the school year, the
  end of the season). The body re-vouches each period.
- **One identifier per relationship.** The holder makes a key per app,
  `relationshipKey(root, appId)`, a Plexus kdf-v1 child
  (`relationship-<hash>:1:0`), so two apps comparing notes cannot link a
  person. For a child the root is their family-plan seat (BitPiggy
  `family/`), so the guardian can recover it.
- **Withdrawal.** The node signs the body's Bitstring Status List; apps fetch it
  whole, so the body never learns who checked whom.
- **Presentation.** The holder's relationship key signs the app's audience and
  one-time nonce over the vouch, as a JWT typed `vp+jwt` so a credential cannot
  pass for one; the app checks the presentation, the vouch, the registry entry,
  the delegation, the dates and the withdrawal list, in that order, without
  contacting the body.

## 3. What a verifier refuses, in order

`bad_presentation`, `wrong_audience`, `wrong_nonce`, `stale`, `bad_credential`,
`subject_mismatch`, `not_registered`, `node_not_delegated`, `claim_not_allowed`,
`not_yet_valid`, `expired`, `no_status_list`, `withdrawn`, `missing_claim`.
The order is the contract: two implementations given the same input must give
the same first reason. The gate also refuses, as `claim_not_allowed`, a vouch
whose expiry is not one of the entry's period ends; as `bad_credential`, a vouch
carrying any term beyond its one claim (a name slipped in, say); and as
`no_status_list`, a vouch pointing at a withdrawal list other than the entry's.
When a body has more than one entry in force (a renewal), the first that
accepts wins. `test/fixtures/bodies_kat.json` pins it for the kids'
world server (Elixir) and any other port.

## 4. Format

W3C VC Data Model 2.0, secured as a JWT with ES256K (secp256k1, the same keys
that recover with Plexus and pay), `did:key` for nodes and holders, `did:web`
for bodies, and Bitstring Status List 1.0 for withdrawal: the deck's choices.
The JWT, did:key and status-list code is a port of BitPiggy's `packages/wire`
(the parent-vouched credentials on its `feat/mailbox` branch). It passes that
package's whole `wire_kat.json`, and signs byte-identical JWTs
(`test/bodies_wire.test.ts`). One difference: status lists are compressed with
`node:zlib` rather than fflate, to keep `@bsv/sdk` the only dependency. Each
decodes the other's lists, but the compressed bytes differ, so a shared
known-answer file should compare a status list by its decoded bits.

## 5. What it does not settle

- **Withdrawing a node.** A replaced node's delegation cannot be withdrawn yet:
  it keeps signing until the body's registry entry is reissued. The fix is a
  second status list, of the body's delegations, checked beside the members'
  one.
- **Who stewards.** The deck's "published rule for which schools count" is now
  a registry entry signed by a steward; who the stewards are is a governance
  question, not a code one. For a one-school pilot the operator can steward,
  said plainly.
- **Bonds and referees.** The deck's money at risk and named referee sit beside
  this, unchanged; a bond can ride in `evidence` next to the delegation.
- **Issuing and presenting endpoints.** OpenID4VCI and OpenID4VP are the
  standards to wrap this in; the pilot can issue over a one-time QR link at the
  office and present inside the app's own sign-in.
- **Linkability across one app.** One credential per relationship stops apps
  linking a person to each other; within one app the identifier is stable by
  design.
- **Self-proven ages.** The L1 range proofs in `src/zk/` remain unaudited; v1
  vouches ages only from a body's records.

## 6. The office

`bodies/office/` is the body's issuing service, a library and a Bun HTTP server
run by or for one body (`bun run office init`, `serve`, `token`). Its state is
one JSON file, mode 0600, written atomically: the node key, the delegation, the
registry entry, the roster, the vouches and the pickups. The anchor key signs
the delegation at `init` and is not kept. Names stay on the roster: no public
answer and no vouch carries a label, group or roster id (the tests scan them).

- **The desk**, behind a bearer token stored hashed: add rows, record consent,
  vouch a class, withdraw a family (with a "guardian may sponsor onward" note),
  and `GET /desk/needs`, the home list of what needs the school.
- **Pickup.** Vouching a consented row makes a one-time 128-bit code, good for
  seven days or to the period end. The parent's phone reads what the body will
  and will not say, then each app's key collects its own vouch with a proof
  `{aud: body, nonce: code, iat}` (OpenID4VCI's `jwt` proof type): up to four
  keys a code, each its own status index, and one key holds one row's vouches.
- **Public**: `/.well-known/did.json` (the anchor as a secp256k1 Multikey) and
  `/status/1`, signed again at each withdrawal. A pilot may sign its own entry
  with a local steward key; `init` warns that a body must not steward itself.
