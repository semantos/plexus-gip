/**
 * The ported wire formats: did:key, ES256K JWTs and Bitstring Status Lists.
 *
 * The vectors marked "bitpiggy" are copied from the bitpiggy wire package's
 * known-answer file (tests/fixtures/wire_kat.json on feat/homework). They pin
 * this port to the same bytes, so the two can later share one file.
 */
import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { PrivateKey } from '@bsv/sdk';
import {
  STATUS_LIST_BITS,
  b64url,
  decodeStatusList,
  didKeyFromPublicKey,
  didKeyOfSecret,
  encodeStatusList,
  fromB64url,
  fromHex,
  fromUtf8,
  hex,
  keyIdFor,
  publicKeyFromDidKey,
  signJwt,
  statusListBit,
  utf8,
  verifyJwt,
  verifyJwtByKid,
} from '../src';

/** bitpiggy dev key for guardian parent-1 under seed 'kat'. */
const BITPIGGY_PARENT_1 = PrivateKey.fromString(
  createHash('sha256').update('bitpiggy-dev:kat:guardian:parent-1').digest('hex'),
  16,
);
const BITPIGGY_PARENT_1_PUB = '02eb86e0204d132a565f7fdca172ad34a4ecc86d0406d6e62ea382c6f591bb7516';
const BITPIGGY_PARENT_1_DID = 'did:key:zQ3shdGBrGQSdBFqWoQaM98hm74DW7soak3mMUpqVEyi3kyho';
/** bitpiggy's GuardianshipCredential, signed by parent-1 with noble. */
const BITPIGGY_GUARDIANSHIP =
  'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJ2Yytqd3QiLCJraWQiOiJkaWQ6a2V5OnpRM3NoZEdCckdRU2RCRnFXb1FhTTk4aG03NERXN3NvYWszbU1VcHFWRXlpM2t5aG8jelEzc2hkR0JyR1FTZEJGcVdvUWFNOThobTc0RFc3c29hazNtTVVwcVZFeWkza3lobyJ9.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJ1cm46Yml0cGlnZ3k6Y29udGV4dDp2MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiR3VhcmRpYW5zaGlwQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJkaWQ6a2V5OnpRM3NoZEdCckdRU2RCRnFXb1FhTTk4aG03NERXN3NvYWszbU1VcHFWRXlpM2t5aG8iLCJ2YWxpZEZyb20iOiIyMDI2LTEwLTIxVDEyOjAwOjAwWiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6UTNzaGRzd044SEpnWHg5Z1VpQzFyV0NiTUJjODRha0Jvb0c5UmM2WXlpZEdqb1h6IiwiaG91c2Vob2xkIjoiMDAxMTIyMzM0NDU1NjY3Nzg4OTlhYWJiY2NkZGVlZmYifSwiY3JlZGVudGlhbFN0YXR1cyI6eyJ0eXBlIjoiQml0c3RyaW5nU3RhdHVzTGlzdEVudHJ5Iiwic3RhdHVzUHVycG9zZSI6InJldm9jYXRpb24iLCJzdGF0dXNMaXN0SW5kZXgiOiIwIiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJiaXRwaWdneTowMDExMjIzMzQ0NTU2Njc3ODg5OWFhYmJjY2RkZWVmZi9zdGF0dXMvelEzc2hkR0JyR1FTZEJGcVdvUWFNOThobTc0RFc3c29hazNtTVVwcVZFeWkza3loby8xIn19.F7AJHKekW59arZlmlMPmyWsv7K6EfbQSiibLqMxd9bhrNeiWHEamR0e2w_AJfJWAIKkY5z6-ooffp2hn3516BQ';
/** The same credential with s replaced by n - s. */
const BITPIGGY_GUARDIANSHIP_HIGH_S = `${BITPIGGY_GUARDIANSHIP.slice(0, BITPIGGY_GUARDIANSHIP.lastIndexOf('.'))}.F7AJHKekW59arZlmlMPmyWsv7K6EfbQSiibLqMxd9biUyhdp47lZuLhJPA_2g2p-mgXD_3CJ_bPgKvYk8JjHPA`;
/** bitpiggy's encodedList for bits 0, 7, 9 and 131071, compressed by fflate. */
const BITPIGGY_ENCODED_LIST = 'uH4sIAAAAAAACA-3AMQEAAAgCMG1mNZsTg2f7GwAAAAAAAAAAAAAAAAAAAKBrAxc7K4AAQAAA';

const payloadOf = (jwt: string) => JSON.parse(fromUtf8(fromB64url(jwt.split('.')[1]!)));

describe('did:key for secp256k1', () => {
  test('matches bitpiggy, round-trips, and starts with zQ3s', () => {
    expect(didKeyFromPublicKey(fromHex(BITPIGGY_PARENT_1_PUB))).toBe(BITPIGGY_PARENT_1_DID);
    expect(didKeyOfSecret(BITPIGGY_PARENT_1)).toBe(BITPIGGY_PARENT_1_DID);
    expect(hex(publicKeyFromDidKey(BITPIGGY_PARENT_1_DID))).toBe(BITPIGGY_PARENT_1_PUB);
    expect(BITPIGGY_PARENT_1_DID.startsWith('did:key:zQ3s')).toBe(true);
  });

  test('refuses another key type, a bad prefix, a bad length and a point off the curve', () => {
    expect(() => publicKeyFromDidKey('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK')).toThrow('wrong_codec');
    expect(() => publicKeyFromDidKey('did:web:example.com')).toThrow('not_did_key');
    expect(() => publicKeyFromDidKey('did:key:uAAAA')).toThrow('not_base58btc');
    expect(() => publicKeyFromDidKey('did:key:zQ3s')).toThrow();
    // x = p, which @bsv/sdk alone would reduce to 0 rather than refuse
    const p = fromHex('02fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f');
    expect(() => publicKeyFromDidKey(didKeyFromPublicKey(p))).toThrow('bad_key');
  });
});

describe('ES256K JWTs', () => {
  test('a bitpiggy credential verifies, and re-signing its payload gives the same bytes', () => {
    const v = verifyJwt(BITPIGGY_GUARDIANSHIP);
    expect(v?.payload.type).toEqual(['VerifiableCredential', 'GuardianshipCredential']);
    expect(v?.header).toEqual({ alg: 'ES256K', typ: 'vc+jwt', kid: keyIdFor(BITPIGGY_PARENT_1_DID) });
    expect(signJwt(payloadOf(BITPIGGY_GUARDIANSHIP), BITPIGGY_PARENT_1)).toBe(BITPIGGY_GUARDIANSHIP);
  });

  test('a high-S signature is refused', () => {
    expect(verifyJwt(BITPIGGY_GUARDIANSHIP_HIGH_S)).toBeNull();
    expect(verifyJwtByKid(BITPIGGY_GUARDIANSHIP_HIGH_S)).toBeNull();
  });

  test('a JWT whose kid names someone other than the issuer does not verify; by kid it does', () => {
    const other = PrivateKey.fromString('22'.repeat(32), 16);
    const payload = { ...payloadOf(BITPIGGY_GUARDIANSHIP), issuer: 'did:web:school.example.edu.au' };
    const jwt = signJwt(payload, other);
    expect(verifyJwt(jwt)).toBeNull();
    expect(verifyJwtByKid(jwt)?.signer).toBe(didKeyOfSecret(other));
  });

  test('an edited payload, a wrong typ and a two-part token are refused', () => {
    const [h, p, s] = BITPIGGY_GUARDIANSHIP.split('.');
    const edited = payloadOf(BITPIGGY_GUARDIANSHIP);
    edited.credentialSubject.household = 'ff'.repeat(16);
    expect(verifyJwt(`${h}.${b64url(utf8(JSON.stringify(edited)))}.${s}`)).toBeNull();
    expect(verifyJwtByKid(BITPIGGY_GUARDIANSHIP, 'vp+jwt')).toBeNull();
    expect(verifyJwt(`${h}.${p}`)).toBeNull();
  });
});

describe('Bitstring Status List', () => {
  test("131072 bits, gzip, bit 0 is the first byte's high bit", () => {
    expect(STATUS_LIST_BITS).toBe(131072);
    const encoded = encodeStatusList([0, 9, 131071]);
    expect(encoded.startsWith('u')).toBe(true);
    const bits = decodeStatusList(encoded);
    expect(bits.length).toBe(16384);
    expect(bits[0]).toBe(0x80);
    expect(bits[1]).toBe(0x40);
    expect([0, 1, 8, 9, 131071].map((i) => statusListBit(bits, i))).toEqual([true, false, false, true, true]);
  });

  test('a list bitpiggy compressed with fflate decodes to the same bits', () => {
    const bits = decodeStatusList(BITPIGGY_ENCODED_LIST);
    const revoked = [0, 7, 9, 131071];
    for (const i of [0, 1, 7, 8, 9, 131070, 131071]) expect(statusListBit(bits, i)).toBe(revoked.includes(i));
    expect(decodeStatusList(encodeStatusList(revoked))).toEqual(bits);
  });

  test('refuses an index off the list, a missing prefix and a short list', () => {
    expect(() => encodeStatusList([131072])).toThrow('bad_status_list');
    expect(() => decodeStatusList(BITPIGGY_ENCODED_LIST.slice(1))).toThrow('multibase');
    const short = `u${b64url(new Uint8Array(Bun.gzipSync(new Uint8Array(1024))))}`;
    expect(() => decodeStatusList(short)).toThrow('16 KiB');
  });
});
