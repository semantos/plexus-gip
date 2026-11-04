/**
 * Bitstring Status List: a withdrawal list fetched whole, so checking a
 * credential tells nobody which one was checked. 131072 bits (16 KiB, the
 * spec's minimum, for herd privacy), GZIP, base64url with multibase prefix
 * 'u'. Bit 0 is the most significant bit of the first byte.
 *
 * Ported from the bitpiggy wire package (`packages/wire/src/statuslist.ts`).
 * It compresses with node:zlib, not fflate, to keep @bsv/sdk the only
 * dependency. Either side decodes the other's lists, but the compressed bytes
 * differ, so a list encoded here is not byte-equal to one encoded there.
 */
import { gunzipSync, gzipSync } from 'node:zlib';
import { WireError, b64url, fromB64url } from './bytes';

export const STATUS_LIST_BITS = 131072;

export function encodeStatusList(revoked: number[]): string {
  const bits = new Uint8Array(STATUS_LIST_BITS / 8);
  for (const i of revoked) {
    if (!Number.isInteger(i) || i < 0 || i >= STATUS_LIST_BITS) throw new WireError('bad_status_list', 'index');
    bits[i >> 3] |= 0x80 >> (i & 7);
  }
  return `u${b64url(new Uint8Array(gzipSync(bits, { level: 9 })))}`;
}

export function decodeStatusList(encodedList: string): Uint8Array {
  if (!encodedList.startsWith('u')) throw new WireError('bad_status_list', 'multibase');
  let bits: Uint8Array;
  try {
    bits = new Uint8Array(gunzipSync(fromB64url(encodedList.slice(1))));
  } catch {
    throw new WireError('bad_status_list', 'gzip');
  }
  if (bits.length < STATUS_LIST_BITS / 8) throw new WireError('bad_status_list', 'shorter than 16 KiB');
  return bits;
}

export const statusListBit = (bits: Uint8Array, index: number): boolean =>
  ((bits[index >> 3] >> (7 - (index & 7))) & 1) === 1;
