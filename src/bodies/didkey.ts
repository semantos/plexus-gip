/**
 * did:key for secp256k1 public keys (multicodec secp256k1-pub 0xe7, varint
 * e7 01, then the 33-byte compressed key, base58btc).
 *
 * Ported from the bitpiggy wire package (`packages/wire/src/didkey.ts`). The
 * curve check uses @bsv/sdk instead of noble, with the same refusals.
 */
import { PublicKey } from '@bsv/sdk';
import { WireError, base58btc, fromBase58btc, hex } from './bytes';

const PREFIX = 'did:key:';

/** The secp256k1 field prime. A compressed x at or above it is not a key. */
const P = 2n ** 256n - 2n ** 32n - 977n;

export function didKeyFromPublicKey(publicKey: Uint8Array): string {
  if (publicKey.length !== 33 || (publicKey[0] !== 2 && publicKey[0] !== 3)) {
    throw new WireError('bad_key', '33-byte compressed secp256k1 key');
  }
  return `${PREFIX}z${base58btc(new Uint8Array([0xe7, 0x01, ...publicKey]))}`;
}

export function publicKeyFromDidKey(did: string): Uint8Array {
  if (!did.startsWith(PREFIX)) throw new WireError('not_did_key', 'expected did:key');
  const multibase = did.slice(PREFIX.length);
  if (!multibase.startsWith('z')) throw new WireError('not_base58btc', 'multibase prefix');
  const bytes = fromBase58btc(multibase.slice(1));
  if (bytes.length < 2 || bytes[0] !== 0xe7 || bytes[1] !== 0x01) throw new WireError('wrong_codec', 'not secp256k1-pub');
  const key = bytes.slice(2);
  if (key.length !== 33 || (key[0] !== 2 && key[0] !== 3)) throw new WireError('bad_key', 'not a compressed key');
  if (!onCurve(key)) throw new WireError('bad_key', 'not on the curve');
  return key;
}

/** The did:key convention: the verification method fragment is the multibase value. */
export const keyIdFor = (did: string): string => `${did}#${did.slice(PREFIX.length)}`;

/**
 * A compressed key names a point. @bsv/sdk reduces x modulo p before it looks
 * for y, so x is range-checked here first, as noble does.
 */
function onCurve(key: Uint8Array): boolean {
  const x = BigInt(`0x${hex(key.slice(1))}`);
  if (x < 1n || x >= P) return false;
  try {
    PublicKey.fromDER(Array.from(key));
    return true;
  } catch {
    return false;
  }
}
