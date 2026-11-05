# The office beside a brain

Each attestor (a school, a club) gets a semantos brain from the operator, with
the workspace cartridge as its home. Its vouch office runs **beside** that
brain, on the same host in Australia, behind the same Caddy: a small Bun
service of its own, not inside the brain and not on Cloudflare. It holds the
body's node key and the children's names, so it stays on a host the operator
runs, where the school's records are allowed to be.

```
                 Caddy (TLS)
   brain.hillside…  /api/v1/vouch/desk/*  ── forward_auth ──►  brain /api/v1/auth/check
                    │   (the caller the brain names, nothing else)
                    └──────────────────────────────────────►  office /desk/*      127.0.0.1:8781
                    everything else  ──────────────────────►  brain               127.0.0.1:<brain port>
   vouch.hillside…  /.well-known/did.json, /status/*, /pickup/*, /collect  ──►  office (everyone)
```

## The desk, behind the brain's login

The registrar signs in to the brain in the Helm the brain serves, with their
wallet, as for anything else on that brain. The desk calls
`/api/v1/vouch/desk/*` on the brain's own host with the Helm's client, which
carries the Helm's bearer for that brain; the desk holds no secret of its own.

Caddy, on the brain's host (`brain-desk.caddy`):

1. drops any `X-Semantos-Standing` or `X-Semantos-Cert-Id` the client sent;
2. asks the brain who the bearer is (`forward_auth` to `GET /api/v1/auth/check`):
   a 401 goes back to the client as it is, a 204 sets those two headers from
   the brain's answer (the standing, such as `operator` or `member`, and the
   identity the wallet login names, a page-0 cert id);
3. drops `Authorization` and `Cookie`, so the brain's credentials go no
   further;
4. passes `/api/v1/vouch/desk/<route>` to the office as `/desk/<route>`.

The office (`serve --desk-auth brain`, as the unit runs it) then takes a desk
request only:

- over loopback (or its own unix socket, `serve --unix`), which is how Caddy
  reaches it;
- with the identity headers, and no `Authorization` or `Cookie` (it refuses a
  request that still carries one, so a Caddy that forgot to strip them is
  found at once);
- from the brain's operator (an operator or admin login), or from a member on
  its registrar list. A hat, a paired device or an agent's bearer is not a
  registrar.

Every desk action is put down to who made it, in the office's own state:
`vouchedBy` on each pickup, `withdrawnBy` on a withdrawn row, and `deskLog`,
one entry per action with row ids and no name.

The office's own site (`Caddyfile`) has no desk at all, and drops the identity
headers on the way to the office too, whatever path a client tries.

### Registrars

The operator may always use the desk. Anyone else is a member of the brain
(enrolled as in `semantos-core docs/operator-runbooks/member-wallet-logins.md`,
with their wallet bound to their identity) and is added by the cert id the
brain names for them. The desk's Setup shows a member their cert id and tells
them to ask the operator.

```sh
sudo -u vouch-office bun bodies/office/cli.ts registrars add <cert id> --label 'Ruth, front office' \
  --state /var/lib/vouch-office/hillside/office.json
sudo -u vouch-office bun bodies/office/cli.ts registrars list   --state …
sudo -u vouch-office bun bodies/office/cli.ts registrars remove <cert id> --state …
```

The office reads its state at every request, so a change takes effect at the
registrar's next request, with no restart. When a registrar leaves, remove
them here; their login on the brain is the operator's to revoke there.

### What loopback trusts

Anything on this host that can open 127.0.0.1:8781 can name a caller to the
office, as Caddy does. The host runs the brain, Caddy and the office, under
their own users; keep it that way. To narrow it to Caddy alone, serve on a
unix socket (`serve --unix /run/vouch-office/hillside/office.sock`, which the
office makes mode 0660), give it a group Caddy is in, and point both
`reverse_proxy` lines at `unix//run/vouch-office/hillside/office.sock`. This
is not the default yet: it has not been run under systemd.

### Development

`serve` without `--desk-auth` is `dev-token`, for development only: the desk
routes take `Authorization: Bearer <token>`, the token `init` prints (and
`cli.ts token` replaces), from anyone who has it. Serve says so loudly. Never
deploy it.

## Files

| File | Goes to |
|---|---|
| `vouch-office@.service` | `/etc/systemd/system/` (one instance per attestor: `vouch-office@hillside`) |
| `office.env.example` | `/etc/vouch-office/<attestor>.env`: the port, no secret |
| `Caddyfile` | the office's public site, in `/etc/caddy/Caddyfile` beside the brain's |
| `brain-desk.caddy` | a `handle` block, pasted into the brain's own site block (`/etc/caddy/conf.d/<brain domain>.conf`) |

## Set up one attestor

```sh
# Once per host: a user, and the code, at a pinned commit.
useradd --system --home /var/lib/vouch-office --shell /usr/sbin/nologin vouch-office
git clone <plexus-gip> /opt/plexus-gip && cd /opt/plexus-gip && git checkout <commit>
bun install --frozen-lockfile

# The state. The anchor key signs the node's delegation here and nowhere else:
# keep it offline. Either run init on an offline machine and copy office.json
# (mode 600) here, or bring the key in for init and take it away again.
install -d -o vouch-office -g vouch-office -m 700 /var/lib/vouch-office/hillside
sudo -u vouch-office bun bodies/office/cli.ts init \
  --state /var/lib/vouch-office/hillside/office.json \
  --did did:web:hillside.example.edu.au --url https://vouch.hillside.example.edu.au \
  --anchor-key <anchor key file> --entry <entry the steward signed>
# init prints a development token: the deploy does not use it.

install -d -m 755 /etc/vouch-office
cp bodies/office/deploy/office.env.example /etc/vouch-office/hillside.env   # then edit it
cp bodies/office/deploy/vouch-office@.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now vouch-office@hillside

# Caddy: add the site from bodies/office/deploy/Caddyfile, with this attestor's
# host and port; paste brain-desk.caddy into the brain's site block, with the
# brain's port and the office's; then
caddy validate --config /etc/caddy/Caddyfile && systemctl reload caddy
```

The brain must serve `GET /api/v1/auth/check` (semantos-core
`runtime/semantos-brain/src/auth_check.zig`); a brain without it answers 404,
which Caddy hands back, and the desk is shut. Re-provisioning the brain's site
rewrites its block: paste the desk in again.

The DID document must be found where the did:web says. If the office is not at
the did's host (here the did is the school's own domain and the office is at
`vouch.`), publish a copy of `https://vouch.…/.well-known/did.json` at
`https://hillside.example.edu.au/.well-known/did.json`; `init` prints both. A
did:web with a path is found at that path, so add it to `@public`.

## Running it

- **Registrars.** `registrars add|remove|list`, above.
- **The node.** `rotate-node --anchor-key <file>`, then `retire-node <old>`
  once holders have collected again (`docs/GIP-V2-BODY-ATTESTATION.md` §6).
- **Backups.** The state file is the office: the node key, the roster, every
  vouch and pickup, the registrars and the desk's record. Back it up
  encrypted, and keep the backups in Australia too. A restored file brings
  back the registrar list that was current then.
- **Logs.** The office logs no request, only an internal error. Caddy keeps no
  access log for the office's site: a pickup URL is a secret until it is used.
  The brain's site may keep one: the desk's paths carry no secret, and Caddy
  leaves credentials out of its logs.
- **Another attestor on the same host** is another instance, port, site and
  desk block.
