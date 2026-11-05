# The office beside a brain

Each attestor (a school, a club) gets a semantos brain from the operator, with
the workspace cartridge as its home. Its vouch office runs **beside** that
brain, on the same host in Australia, behind the same Caddy: a small Bun
service of its own, not inside the brain and not on Cloudflare. It holds the
body's node key and the children's names, so it stays on a host the operator
runs, where the school's records are allowed to be.

```
              Caddy (TLS)
   brain.hillside…  ──────────────►  brain   127.0.0.1:<brain port>   (serves the Helm)
   vouch.hillside…  /.well-known/did.json, /status/*, /pickup/*, /collect  (everyone)
                    /desk/*  (only with Origin: the brain)  ──►  office  127.0.0.1:8781
```

The registrar uses the desk in the Helm the brain serves. For now the desk
calls the office's `/desk/*` routes with the office's own registrar token; the
office answers that browser because it is told the brain's origin
(`--desk-origin`), and wants the token whatever the origin.

## Files

| File | Goes to |
|---|---|
| `vouch-office@.service` | `/etc/systemd/system/` (one instance per attestor: `vouch-office@hillside`) |
| `office.env.example` | `/etc/vouch-office/<attestor>.env`: the port and the desk's origin, no secret |
| `Caddyfile` | a site in `/etc/caddy/Caddyfile`, beside the brain's |

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
# init prints the registrar token once: give it to the registrar, for the desk's Setup.

install -d -m 755 /etc/vouch-office
cp bodies/office/deploy/office.env.example /etc/vouch-office/hillside.env   # then edit it
cp bodies/office/deploy/vouch-office@.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now vouch-office@hillside

# Caddy: add the site from bodies/office/deploy/Caddyfile, with this attestor's
# hosts and port, then
systemctl reload caddy
```

The DID document must be found where the did:web says. If the office is not at
the did's host (here the did is the school's own domain and the office is at
`vouch.`), publish a copy of `https://vouch.…/.well-known/did.json` at
`https://hillside.example.edu.au/.well-known/did.json`; `init` prints both. A
did:web with a path is found at that path, so add it to `@public`.

## Running it

- **The token.** `cli.ts token --state …` makes a new one; the old one stops at
  once. Do it when a registrar leaves.
- **The node.** `rotate-node --anchor-key <file>`, then `retire-node <old>`
  once holders have collected again (`docs/GIP-V2-BODY-ATTESTATION.md` §6).
- **Backups.** The state file is the office: the node key, the roster, every
  vouch and pickup. Back it up encrypted, and keep the backups in Australia
  too. A restored file brings back the token that was current then.
- **Logs.** The office logs no request, only an internal error. Caddy keeps no
  access log for this site: a pickup URL is a secret until it is used.
- **Another attestor on the same host** is another instance, port and site.
