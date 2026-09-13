/**
 * The FamilySearch certifier CLI (kit build).
 *
 *     bun cli.ts keygen                 # create the certifier key (stays local)
 *     bun cli.ts pubkey                 # its public key — put this in a verifier's trusted set
 *     bun cli.ts fs-vouch-kin       <subjectPubkey> <relation> <counterpartPubkey>
 *     bun cli.ts fs-attest-record   <subjectPubkey> <recordHash>
 *     bun cli.ts fs-attest-predicate <subjectPubkey> '<predicate>'   # quote it, e.g. 'gen-depth>=3'
 *
 * The key never leaves this machine; each command prints a portable signed leaf
 * the holder folds into their own set. `CERTIFIER_KEY_PATH` overrides the key
 * location. This is the trimmed, self-contained twin of semantos-core's
 * `cartridges/boomspace/certify.ts` (the `fs-*` commands only).
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname } from 'node:path';
import { PrivateKey } from '@bsv/sdk';
import { runFsAttestPredicate, runFsAttestRecord, runFsVouchKin } from './sign';

const KEY_PATH = process.env.CERTIFIER_KEY_PATH ?? `${homedir()}/.gip-v2/certifier-key`;

function loadCertifier(): PrivateKey {
  if (!existsSync(KEY_PATH)) throw new Error(`no certifier key at ${KEY_PATH} — run \`bun cli.ts keygen\` first`);
  return PrivateKey.fromString(readFileSync(KEY_PATH, 'utf8').trim(), 16);
}

function keygen(): void {
  if (existsSync(KEY_PATH)) throw new Error(`refusing to overwrite ${KEY_PATH} — a new certifier orphans every existing attestation`);
  mkdirSync(dirname(KEY_PATH), { recursive: true, mode: 0o700 });
  const sk = PrivateKey.fromRandom();
  writeFileSync(KEY_PATH, sk.toString(), { mode: 0o600 });
  console.log(`certifier key written to ${KEY_PATH} (mode 600)`);
  console.log(`public key: ${sk.toPublicKey().toString()}`);
  console.log('\nPut the PUBLIC key in a verifier’s trusted-certifier set. Keep the private key here.');
}

const HELP = `commands: keygen | pubkey | fs-vouch-kin | fs-attest-record | fs-attest-predicate
  bun cli.ts fs-vouch-kin        <subjectPubkey> <relation> <counterpartPubkey>
  bun cli.ts fs-attest-record    <subjectPubkey> <recordHash>
  bun cli.ts fs-attest-predicate <subjectPubkey> 'gen-depth>=3'`;

const [cmd, ...rest] = process.argv.slice(2);
if (cmd === 'keygen') keygen();
else if (cmd === 'pubkey') console.log(loadCertifier().toPublicKey().toString());
else if (cmd === 'fs-vouch-kin') console.log(runFsVouchKin(loadCertifier(), rest));
else if (cmd === 'fs-attest-record') console.log(runFsAttestRecord(loadCertifier(), rest));
else if (cmd === 'fs-attest-predicate') console.log(runFsAttestPredicate(loadCertifier(), rest));
else if (cmd === '--help' || cmd === undefined) console.log(HELP);
else {
  console.error(`unknown command: ${cmd}\n${HELP}`);
  process.exit(1);
}
