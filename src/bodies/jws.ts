/**
 * Credentials as JWTs signed with ES256K (VC-JOSE-COSE): header
 * {alg: ES256K, typ: vc+jwt, kid: <did:key>#<multibase>}, the payload is the
 * credential itself, the signature is ECDSA secp256k1 over SHA-256 of the
 * ASCII signing input, 64 bytes r||s, low-S.
 *
 * Ported from the bitpiggy wire package (`packages/wire/src/jws.ts`). The
 * curve maths is @bsv/sdk's rather than noble's. Both sign by RFC 6979, so the
 * same key and payload give the same bytes, and both refuse a high-S
 * signature.
 *
 * Two additions. A presentation is typed `vp+jwt`, so a credential cannot be
 * passed off as one. And {@link verifyJwtByKid} takes the key from the header,
 * for a credential whose issuer is a did:web and whose signer is a node the
 * issuer delegated.
 */
import { BigNumber, PrivateKey, PublicKey, Signature } from '@bsv/sdk';
import { b64url, fromB64url, fromHex, fromUtf8, hex, utf8 } from './bytes';
import { didKeyFromPublicKey, keyIdFor, publicKeyFromDidKey } from './didkey';

export const VC_CONTEXT = 'https://www.w3.org/ns/credentials/v2';

/**
 * `openid4vci-proof+jwt` is a holder's proof of its key when it collects a
 * credential (OpenID4VCI's `jwt` proof type): {aud: the issuer, nonce, iat}.
 * It has its own type, so a presentation cannot be passed off as one.
 */
export type JwtTyp = 'vc+jwt' | 'vp+jwt' | 'openid4vci-proof+jwt';

export interface JwtHeader {
  alg: 'ES256K';
  typ: JwtTyp;
  kid: string;
}

/** Order of the secp256k1 group, and half of it for the low-S rule. */
const N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
const HALF_N = N >> 1n;

/** The did:key of a private key's public key. */
export const didKeyOfSecret = (sk: PrivateKey): string => didKeyFromPublicKey(fromHex(sk.toPublicKey().toString()));

/** ECDSA secp256k1 over SHA-256(message): 64 bytes r||s, low-S, RFC 6979 nonce. */
export function es256kSign(sk: PrivateKey, message: Uint8Array): Uint8Array {
  const sig = sk.sign(Array.from(message)); // @bsv/sdk forces low-S by default
  return new Uint8Array([...sig.r.toArray('be', 32), ...sig.s.toArray('be', 32)]);
}

/** Verify a 64-byte r||s signature. A high-S signature is refused, as noble refuses it. */
export function es256kVerify(sig: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    if (sig.length !== 64) return false;
    const r = BigInt(`0x${hex(sig.slice(0, 32))}`);
    const s = BigInt(`0x${hex(sig.slice(32))}`);
    if (r === 0n || r >= N || s === 0n || s > HALF_N) return false;
    const signature = new Signature(new BigNumber(hex(sig.slice(0, 32)), 16), new BigNumber(hex(sig.slice(32)), 16));
    return PublicKey.fromDER(Array.from(publicKey)).verify(Array.from(message), signature);
  } catch {
    return false;
  }
}

export function signJwt(payload: Record<string, unknown>, signer: PrivateKey, typ: JwtTyp = 'vc+jwt'): string {
  const header: JwtHeader = { alg: 'ES256K', typ, kid: keyIdFor(didKeyOfSecret(signer)) };
  const input = `${b64url(utf8(JSON.stringify(header)))}.${b64url(utf8(JSON.stringify(payload)))}`;
  return `${input}.${b64url(es256kSign(signer, utf8(input)))}`;
}

export interface VerifiedJwt {
  header: JwtHeader;
  payload: Record<string, any>;
}

/** Null unless the JWT is well formed, names its issuer as the key, and that key signed it. */
export function verifyJwt(jwt: string): VerifiedJwt | null {
  try {
    const parts = jwt.split('.');
    if (parts.length !== 3) return null;
    const header = JSON.parse(fromUtf8(fromB64url(parts[0]!)));
    const payload = JSON.parse(fromUtf8(fromB64url(parts[1]!)));
    if (header?.alg !== 'ES256K' || header?.typ !== 'vc+jwt') return null;
    if (typeof payload !== 'object' || payload === null || typeof payload.issuer !== 'string') return null;
    if (header.kid !== keyIdFor(payload.issuer)) return null;
    if (!isVcShape(payload)) return null;
    const sig = fromB64url(parts[2]!);
    if (sig.length !== 64) return null;
    const key = publicKeyFromDidKey(payload.issuer);
    if (!es256kVerify(sig, utf8(`${parts[0]}.${parts[1]}`), key)) return null;
    return { header, payload };
  } catch {
    return null;
  }
}

/** A JWT checked against the key its header names. */
export interface SignedJwt extends VerifiedJwt {
  /** The did:key that signed it. */
  signer: string;
}

/**
 * Null unless the JWT is well formed, its `kid` is a did:key verification
 * method, and that key signed it. Who the issuer is, and whether this signer
 * may speak for it, is the caller's business. A `vc+jwt` must also have the
 * credential shape {@link verifyJwt} asks for.
 */
export function verifyJwtByKid(jwt: string, typ: JwtTyp = 'vc+jwt'): SignedJwt | null {
  try {
    const parts = jwt.split('.');
    if (parts.length !== 3) return null;
    const header = JSON.parse(fromUtf8(fromB64url(parts[0]!)));
    const payload = JSON.parse(fromUtf8(fromB64url(parts[1]!)));
    if (header?.alg !== 'ES256K' || header?.typ !== typ || typeof header.kid !== 'string') return null;
    if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) return null;
    const signer = header.kid.split('#')[0]!;
    if (header.kid !== keyIdFor(signer)) return null;
    if (typ === 'vc+jwt' && (typeof payload.issuer !== 'string' || !isVcShape(payload))) return null;
    const sig = fromB64url(parts[2]!);
    if (sig.length !== 64) return null;
    const key = publicKeyFromDidKey(signer);
    if (!es256kVerify(sig, utf8(`${parts[0]}.${parts[1]}`), key)) return null;
    return { header, payload, signer };
  } catch {
    return null;
  }
}

function isVcShape(payload: Record<string, any>): boolean {
  if (!Array.isArray(payload['@context']) || payload['@context'][0] !== VC_CONTEXT) return false;
  if (!Array.isArray(payload.type) || payload.type.length !== 2 || payload.type[0] !== 'VerifiableCredential') return false;
  return typeof payload.type[1] === 'string';
}
