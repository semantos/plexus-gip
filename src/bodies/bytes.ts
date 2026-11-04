/**
 * Byte helpers that run the same in Bun, browsers and Workers (no Buffer).
 *
 * Ported from the bitpiggy wire package (`packages/wire/src/bytes.ts`) with
 * the same behaviour, so the two can share one known-answer file.
 */

export class WireError extends Error {
  constructor(
    readonly code: string,
    detail?: string,
  ) {
    super(detail ? `${code}: ${detail}` : code);
  }
}

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
export const fromUtf8 = (b: Uint8Array): string =>
  new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(b);

export const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

export function fromHex(s: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})*$/.test(s)) throw new WireError('hex', 'lowercase hex, even length');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** base64url without padding (RFC 4648 §5), as JWS uses. */
export function b64url(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64URL[n >> 18] + B64URL[(n >> 12) & 63] + B64URL[(n >> 6) & 63] + B64URL[n & 63];
  }
  if (bytes.length - i === 1) {
    const n = bytes[i] << 16;
    out += B64URL[n >> 18] + B64URL[(n >> 12) & 63];
  } else if (bytes.length - i === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64URL[n >> 18] + B64URL[(n >> 12) & 63] + B64URL[(n >> 6) & 63];
  }
  return out;
}

/** Strict: no padding, no other alphabet, no trailing bits set. */
export function fromB64url(s: string): Uint8Array {
  if (s.length % 4 === 1) throw new WireError('base64url', 'length');
  const vals: number[] = [];
  for (const ch of s) {
    const v = B64URL.indexOf(ch);
    if (v < 0) throw new WireError('base64url', 'alphabet');
    vals.push(v);
  }
  const out = new Uint8Array(Math.floor((vals.length * 6) / 8));
  let acc = 0;
  let bits = 0;
  let j = 0;
  for (const v of vals) {
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[j++] = (acc >> bits) & 0xff;
    }
  }
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) throw new WireError('base64url', 'trailing bits');
  return out;
}

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58btc(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let k = 0; k < digits.length; k++) {
      carry += digits[k] << 8;
      digits[k] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  return '1'.repeat(zeros) + digits.reverse().map((d) => B58[d]).join('');
}

export function fromBase58btc(s: string): Uint8Array {
  let zeros = 0;
  while (zeros < s.length && s[zeros] === '1') zeros++;
  const bytes: number[] = [];
  for (let i = zeros; i < s.length; i++) {
    const v = B58.indexOf(s[i]);
    if (v < 0) throw new WireError('not_base58btc', 'alphabet');
    let carry = v;
    for (let k = 0; k < bytes.length; k++) {
      carry += bytes[k] * 58;
      bytes[k] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  return new Uint8Array([...new Array(zeros).fill(0), ...bytes.reverse()]);
}
