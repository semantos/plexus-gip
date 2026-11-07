# Any body as attestor

**Status:** built in `src/bodies/`, tested in `test/bodies.test.ts`, pinned by
`test/fixtures/bodies_kat.json`; nothing live. 4 November 2026. On 5 November
the node's delegation moved out of every vouch and onto the withdrawal list
(Todd's decision, so a seat card with several vouches fits one QR code).
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
 body root (anchor, Plexus page-0) ── delegateSigner(…, 'body.vouch') ──▶ signing node(s) (hosted)
 signing node ── signs ──▶ vouch (VC 2.0, ES256K JWT) about the holder's key for ONE relationship; no delegation in it
                     └──▶ withdrawal list (Bitstring Status List), fetched whole, carrying each honoured node's delegation
 holder ── signs the app's one-time challenge ──▶ presentation ──▶ app checks everything offline
```

- **Who counts.** A registry entry (`BodyRegistryEntryCredential`) is signed by
  a steward the verifier trusts. It names the body's `did:web`, its anchor key,
  its kind, the claims it may vouch, the period ends its vouches may expire on,
  and its withdrawal list. A steward cannot register itself: a body vouching
  for itself counts for nothing.
- **Day-to-day signing.** The body's root never signs a vouch. It signs a GIP
  delegation (`delegateSigner(root, node, 'body.vouch')`) to a hosted node.
  This is the deck's "proof that a hosted node acts for its school". The
  delegation does not travel in the vouch: the withdrawal list carries it, as
  `evidence: [{type: 'SigningNodeDelegation', delegation}, …]`, one for each
  node the body still honours, and one of those nodes signs the list. A vouch
  that carries `evidence` is refused, so there is one format. The verifier's
  trust stays with the root.
- **A new node, and withdrawing one.** Replacing the node is a new delegation:
  the new node signs the list, and the list carries both delegations while
  the old node's vouches are still to be honoured. Withdrawing a node is
  taking its delegation off the list and signing it again; every vouch that
  node signed then fails with `node_not_delegated` at the app's next download.
  It holds only while the app takes the list from the entry's URL and nowhere
  else: a withdrawn node's key can still sign a list carrying its own old
  delegation.
- **Expiry is a period end, never a birthday.** A credential that expired on a
  child's 13th birthday would give the birthdate away, so `validUntil` must be
  one of the entry's published period ends (the end of the school year, the
  end of the season). The body re-vouches each period.
- **One identifier per place.** The holder makes a key per place,
  `placeKeyOf(root, place)` (`src/places/`): BRC-42 to the root itself under
  `2-admin plexus site-<place> 1`, where a place is a web site's origin
  (`https://lessons.example`) or `app:<id>` for an app
  (`app:kids-world:gem-island`). So two places comparing notes cannot link a
  person, and at a web site it is the key the Plexus Auth approver signs in
  with, so the key that signs in is the key the vouch names (semantos-core
  `CLAIMS-AND-REQUIREMENTS.md`, decision 11, which replaced the earlier
  `relationshipKey`). For a child the root is their family-plan seat (BitPiggy
  `family/`), so the guardian can recover it.
- **Withdrawal.** The node signs the body's Bitstring Status List; apps fetch it
  whole, so the body never learns who checked whom. The same download says
  which nodes still count.
- **Presentation.** The holder's place key signs the app's audience and
  one-time nonce over the vouch, as a JWT typed `vp+jwt` so a credential cannot
  pass for one; the app checks the presentation, the vouch, the registry entry,
  the withdrawal list and the delegations on it, the claim, the dates and the
  vouch's bit, in that order, without contacting the body.

## 3. What a verifier refuses, in order

`bad_presentation`, `wrong_audience`, `wrong_nonce`, `stale`, `bad_credential`,
`subject_mismatch`, `not_registered`, `no_status_list`, `node_not_delegated`,
`claim_not_allowed`, `not_yet_valid`, `expired`, `withdrawn`, `missing_claim`.
The order is the contract: two implementations given the same input must give
the same first reason. The list now comes before the node's delegation, the
claim and the dates, because the delegations are on it.

- `bad_credential` also covers a vouch carrying any term beyond its one claim
  (a name slipped in, say) and a vouch carrying `evidence` at all.
- `no_status_list`: no list held for the entry's `statusList` URL; or the list
  is malformed, its signature fails, it is for another body or URL or not yet
  valid; or its signer (`kid`) is not delegated, for `body.vouch`, by the
  entry's anchor in the list's own evidence; or the vouch's status entry
  points at another URL.
- `node_not_delegated`: the vouch's signer (`kid`) is not delegated, for
  `body.vouch`, by the entry's anchor in the list's evidence.
- `claim_not_allowed` also covers an expiry that is not one of the entry's
  period ends.

When a body has more than one entry in force (a renewal), the first that
accepts wins. `test/fixtures/bodies_kat.json` pins it for the kids' world
server (Elixir) and any other port. It pins a rotation: node-1 signed the
vouch, node-2 signs the list, and the list carries both delegations, node-2's
first, so a port that looks only at the first delegation, or only at the list
signer's, gets it wrong.

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

Sizes, from the known-answer file (a `member` vouch): a vouch JWT is 980
bytes, down from 1,528 when it carried the delegation, and a presentation is
1,699 bytes, down from 2,430. The largest QR code (version 40, level L) holds
2,953 bytes, so a vouch went from just over half of one to a third. The list
grows instead, by about 530 bytes for each node it honours (1,454 bytes with
one, 1,984 with two), and an app fetches it once for the whole body.

## 5. What it does not settle

- **Who stewards.** The deck's "published rule for which schools count" is now
  a registry entry signed by a steward; who the stewards are is a governance
  question, not a code one. For a one-school pilot the operator can steward,
  said plainly.
- **Bonds and referees.** The deck's money at risk and named referee sit beside
  this, unchanged. A bond is the body's, so it would ride on the list beside
  the delegations, never in a vouch.
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
run by or for one body (`bun run office init`, `serve`, `registrars`, `token`,
`rotate-node`, `retire-node`). Its state is one JSON file, mode 0600, written
atomically: the node key, the delegations the body honours (the current node's
first), the registry entry, the roster, the vouches and the pickups, the
registrars and the desk's record of who did what. The anchor key signs
a node's delegation at `init` and at `rotate-node`, and is not kept. Names stay
on the roster: no public answer and no vouch carries a label, group or roster
id (the tests scan them).

- **The desk**: add rows, record consent,
  vouch a class, withdraw a family (with a "guardian may sponsor onward" note),
  `GET /desk/needs`, the home list of what needs the school (its counts split
  the rows vouched into members and guardians), and `GET /desk/standing`,
  where the body stands: the registry entry as its steward signed it (did,
  kind, claims, period ends, the steward, whether it is a pilot's own, when it
  holds), the DID document's place, the anchor, the signing node and every
  node the list honours, and the withdrawal list (its URL, when the list now
  published was signed, and how many places it marks withdrawn).
- **Who may use the desk** (`serve --desk-auth`). The registrar's desk is the
  vouch cartridge in the Helm (semantos-core `packages/vouch_experience`).
  - `brain`, for a deploy: the registrar signs in to the body's brain in the
    Helm, and the desk calls `/api/v1/vouch/desk/*` on the brain's host with
    the Helm's own client, so it holds no secret. Caddy there drops any
    `X-Semantos-Standing` or `X-Semantos-Cert-Id` the client sent, asks the
    brain who the bearer is (`forward_auth` to `GET /api/v1/auth/check`, which
    answers 204 with the standing and the page-0 cert id its wallet login
    names, or 401), sets the two headers from that answer, drops
    `Authorization` and `Cookie`, and passes the request on as `/desk/*`. The
    office takes it only over loopback or its own unix socket, only with the
    headers and without the brain's credentials (a request still carrying
    either is 400 `brain_credential_forwarded`), and only from the brain's
    operator (or admin) or a member whose cert id is on its registrar list
    (`registrars add|remove|list`): anyone else is 403 `not_a_registrar`,
    with what to do. A hat, a device or an agent's bearer is not a registrar.
    `GET /desk/whoami` says who the office takes the caller to be and whether
    it lets them in. `deploy/` has the Caddy blocks.
  - `dev-token`, the default, for development only: `Authorization: Bearer
    <token>`, stored hashed, made at `init` and by `token`. `serve` says so.
  Every desk action is put down to who made it: `vouchedBy` on a pickup,
  `withdrawnBy` on a withdrawn row, and one `deskLog` entry per action, by row
  id, with no name.
- **The desk's origin.** A Helm served from another origin than the brain's
  host is a browser on that origin, so `serve --desk-origin <origin>[,<origin>]`
  (or `$OFFICE_DESK_ORIGIN`) names the origins a browser may call `/desk/*`
  from. A preflight from one gets the route's methods and the `authorization`
  header; any other is 403 `origin_not_allowed`; an answer to one carries it,
  with `Vary: Origin`. This is CORS, not a lock: the desk still asks who is
  calling, from any origin. The Helm the brain serves needs none.
- **Pickup.** Vouching a consented row makes a one-time 128-bit code, good for
  seven days or to the period end. The parent's phone reads what the body will
  and will not say, then each app's key collects its own vouch with a proof
  `{aud: body, nonce: code, iat}` (OpenID4VCI's `jwt` proof type): up to four
  keys a code, each its own status index, and one key holds one row's vouches.
- **Finding the office.** A seat card carries only the child's key and where
  to look; the device collects its vouches from each body's office (Todd's
  decision, 5 November 2026). The DID document the office serves names it:
  `service: [{id: <did>#vouch-office, type: BodyVouchOffice, serviceEndpoint:
  <office base URL>}]`. A device resolves the body's did:web as the DID Web
  method says (`did:web:host%3Aport:path` is `https://host:port/path/did.json`,
  and with no path `/.well-known/did.json`) and reads the endpoint from the
  document: `didWebDocumentUrl` and `vouchOfficeOf` in `src/bodies/didweb.ts`,
  which build and read and never fetch. `allowHttpLocal` lets a reader use
  http for `localhost` and `127.0.0.1`, for local work and tests only.
- **Collecting.** `POST /collect {proof}` takes the pickup's proof with the
  nonce `collect`, `{aud: body, nonce: "collect", iat}`, refused (400) if more
  than 300 s from the office's clock, for another audience or with another
  nonce. The answer is `{vouches: [...]}`: every vouch about that key that is
  neither withdrawn nor ended, newest period first, each signed by the
  current node, so after `rotate-node` the device gets the same vouch (place
  and dates) under the new node's signature. An unknown key gets `{vouches:
  []}`, the same as a key with nothing live, so the route cannot be used to
  ask whether a key is known. No label, group or roster id is in the answer.
- **Renewal.** When the registrar vouches a row again for a later period
  (`/desk/vouch` with a later `periodEnd`), every key holding a live or
  lapsed vouch of that row collects the new period's vouch the next time it
  collects, with no new code: issued at collect time, at a new random place,
  valid from the day the registrar vouched. This period's vouches stay live
  beside it. A withdrawn row, or one without consent, gets nothing new. A
  withdrawal is final for the vouches it withdraws: a row taken back renews
  its keys only from periods vouched after, and a withdrawn key needs a code.
  The home list does not show a row vouched for a later period as lapsing.
- **Nodes.** `rotate-node --anchor-key <file>` makes a new node key; the
  anchor key signs its delegation, the new node signs the list, and the old
  node's delegation stays on it, so its vouches still pass. `retire-node
  <node>` takes an old node's delegation off: every vouch that node signed
  then fails with `node_not_delegated`. A device that collected after the
  rotation already holds the same vouch from the new node, so retire an old
  node once holders have collected, or at once if its key may be lost. The
  current node cannot be retired. The list is signed again whenever the
  delegations change.
- **Public**: `/.well-known/did.json` (the anchor as a secp256k1 Multikey, and
  the office as a service), `/status/1`, signed again at each withdrawal and
  each change of node, `/pickup/<code>` and `POST /collect`. A pilot may sign
  its own entry with a local steward key; `init` warns that a body must not
  steward itself.
- **Where it runs** (Todd's decision, 5 November 2026). Each attestor gets a
  semantos brain from the operator, with the workspace cartridge as its home,
  and its office runs beside that brain on the same host in Australia, behind
  the same Caddy: not inside the brain, and not on Cloudflare, since it holds
  the node key and the children's names. `bodies/office/deploy/` has the
  recipe: `vouch-office@.service`, one instance per attestor, runs
  `bun --no-install run bodies/office/cli.ts serve --desk-auth brain` on
  127.0.0.1 with its state in `/var/lib/vouch-office/<attestor>/` (0700) and
  its port from `/etc/vouch-office/<attestor>.env`, which holds no secret; the
  `Caddyfile` site serves `/.well-known/did.json`, `/status/*`, `/pickup/*`
  and `/collect` to everyone with no caller passed on, no desk, 404 for the
  rest, and keeps no access log, since a pickup URL is a secret until it is
  used; `brain-desk.caddy` is the desk's block for the brain's own site. The
  brain's own Caddy template (semantos-core `caddy_template.zig`) writes both
  when the brain's manifest has `[vouch_office]`; these two are the same by
  hand, and a test holds them to the template's. Its
  README covers init with the anchor key kept offline, a DID document
  published at the did's host when the office is elsewhere, and backups of
  the state file, encrypted and in Australia.
