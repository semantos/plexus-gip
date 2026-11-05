/**
 * Reading a did:web (`src/bodies/didweb.ts`): where its DID document is, by
 * the DID Web method's own examples, and where the body's office is, from the
 * document. No network: the reader fetches, these build and read.
 */
import { describe, expect, test } from 'bun:test';
import { BODY_VOUCH_OFFICE, didWebDocumentUrl, didWebHost, didWebPath, vouchOfficeOf } from '../src';

describe('didWebDocumentUrl', () => {
  test('the DID Web method\'s examples', () => {
    const cases: [string, string][] = [
      ['did:web:w3c-ccg.github.io', 'https://w3c-ccg.github.io/.well-known/did.json'],
      ['did:web:w3c-ccg.github.io:user:alice', 'https://w3c-ccg.github.io/user/alice/did.json'],
      ['did:web:example.com', 'https://example.com/.well-known/did.json'],
      ['did:web:example.com%3A3000', 'https://example.com:3000/.well-known/did.json'],
      ['did:web:example.com%3A3000:user:alice', 'https://example.com:3000/user/alice/did.json'],
      ['did:web:example.com%3a3000:user:alice', 'https://example.com:3000/user/alice/did.json'],
      ['did:web:hillside.example.edu.au', 'https://hillside.example.edu.au/.well-known/did.json'],
      ['did:web:example.com:schools:hill_side-2.0', 'https://example.com/schools/hill_side-2.0/did.json'],
      ['did:web:example.com:a%20b', 'https://example.com/a%20b/did.json'],
    ];
    for (const [did, url] of cases) {
      expect(didWebDocumentUrl(did)).toBe(url);
      expect(URL.parse(url)?.href).toBe(url);
    }
  });

  test('the host, with its port, and the path on it', () => {
    expect(didWebHost('did:web:example.com%3A3000:user:alice')).toBe('example.com:3000');
    expect(didWebPath('did:web:example.com%3A3000:user:alice')).toBe('/user/alice/did.json');
    expect(didWebHost('did:web:example.com')).toBe('example.com');
    expect(didWebPath('did:web:example.com')).toBe('/.well-known/did.json');
  });

  test('http for localhost and 127.0.0.1 only, and only when told', () => {
    expect(didWebDocumentUrl('did:web:localhost%3A8080')).toBe('https://localhost:8080/.well-known/did.json');
    expect(didWebDocumentUrl('did:web:localhost%3A8080', { allowHttpLocal: true })).toBe('http://localhost:8080/.well-known/did.json');
    expect(didWebDocumentUrl('did:web:localhost', { allowHttpLocal: true })).toBe('http://localhost/.well-known/did.json');
    expect(didWebDocumentUrl('did:web:127.0.0.1%3A8080:office', { allowHttpLocal: true })).toBe('http://127.0.0.1:8080/office/did.json');
    expect(didWebDocumentUrl('did:web:example.com%3A8080', { allowHttpLocal: true })).toBe('https://example.com:8080/.well-known/did.json');
    expect(didWebDocumentUrl('did:web:localhost.example.com', { allowHttpLocal: true })).toBe('https://localhost.example.com/.well-known/did.json');
    // The method allows no IP address; 127.0.0.1 is let through for local work only.
    expect(() => didWebDocumentUrl('did:web:127.0.0.1%3A8080')).toThrow('bad_did');
  });

  test('anything else is refused', () => {
    const bad = [
      'did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme',
      'did:web:',
      'did:web',
      'web:example.com',
      'did:web:10.0.0.1',
      'did:web:192.168.1.20%3A8080',
      'did:web:0x7f.1',
      'did:web:example.com%3A',
      'did:web:example.com%3A0',
      'did:web:example.com%3A65536',
      'did:web:example.com%3A08080',
      'did:web:example.com%3Ax',
      'did:web:example.com::user',
      'did:web:example.com:user:',
      'did:web:example.com:..',
      'did:web:example.com:.',
      'did:web:example.com:%2e%2E',
      'did:web:example.com:a%2Fb',
      'did:web:example.com:a%5Cb',
      'did:web:example.com:a%zz',
      'did:web:example.com/user',
      'did:web:example.com#key-1',
      'did:web:example.com?x=1',
      'did:web:user@example.com',
      'did:web:Example.com',
      'did:web:exa mple.com',
      'did:web:-example.com',
      'did:web:example..com',
      'did:web:example.com.',
      'did:web:example.com%2Fuser',
      'did:web:example.com%3A3000%3A4000',
    ];
    for (const did of bad) expect(() => didWebDocumentUrl(did, { allowHttpLocal: true }), did).toThrow('bad_did');
  });
});

describe('vouchOfficeOf', () => {
  const DID = 'did:web:hillside.example.edu.au';
  const doc = (service: unknown, id = DID) => ({ '@context': ['https://www.w3.org/ns/did/v1'], id, ...(service !== undefined && { service }) });
  const office = (serviceEndpoint: unknown, type: unknown = BODY_VOUCH_OFFICE) => ({ id: `${DID}#vouch-office`, type, serviceEndpoint });

  test('the endpoint of the BodyVouchOffice service', () => {
    expect(BODY_VOUCH_OFFICE).toBe('BodyVouchOffice');
    expect(vouchOfficeOf(doc([office('https://hillside.example.edu.au')]), DID)).toBe('https://hillside.example.edu.au');
    expect(vouchOfficeOf(doc([office('https://office.example.org:8443/hillside/')]), DID)).toBe('https://office.example.org:8443/hillside');
    // A type may be a set; another service before it is passed over.
    const other = { id: `${DID}#hub`, type: 'LinkedDomains', serviceEndpoint: 'https://elsewhere.example.org' };
    expect(vouchOfficeOf(doc([other, office('https://office.example.org', ['Other', BODY_VOUCH_OFFICE])]), DID)).toBe(
      'https://office.example.org',
    );
  });

  test('null for a document of another did, no office, or an endpoint a reader may not use', () => {
    const ok = office('https://hillside.example.edu.au');
    expect(vouchOfficeOf(doc([ok], 'did:web:other.example.org'), DID)).toBeNull();
    expect(vouchOfficeOf(doc(undefined), DID)).toBeNull();
    expect(vouchOfficeOf(doc([]), DID)).toBeNull();
    expect(vouchOfficeOf(doc(ok), DID)).toBeNull();
    expect(vouchOfficeOf(null, DID)).toBeNull();
    expect(vouchOfficeOf('{}', DID)).toBeNull();
    expect(vouchOfficeOf(doc([office('https://x.example.org', 'LinkedDomains')]), DID)).toBeNull();
    for (const endpoint of [
      'http://hillside.example.edu.au',
      'http://localhost:8080',
      'ftp://hillside.example.edu.au',
      'https://hillside.example.edu.au/?x=1',
      'https://hillside.example.edu.au/#x',
      'https://user:pw@hillside.example.edu.au',
      'not a url',
      ['https://hillside.example.edu.au'],
      { origins: ['https://hillside.example.edu.au'] },
      42,
    ]) {
      expect(vouchOfficeOf(doc([office(endpoint)]), DID)).toBeNull();
    }
  });

  test('http on localhost or 127.0.0.1 when told', () => {
    const LOCAL = 'did:web:localhost%3A8080';
    const local = (endpoint: string) => doc([{ id: `${LOCAL}#vouch-office`, type: BODY_VOUCH_OFFICE, serviceEndpoint: endpoint }], LOCAL);
    expect(vouchOfficeOf(local('http://localhost:8080'), LOCAL)).toBeNull();
    expect(vouchOfficeOf(local('http://localhost:8080'), LOCAL, { allowHttpLocal: true })).toBe('http://localhost:8080');
    expect(vouchOfficeOf(local('http://127.0.0.1:8080'), LOCAL, { allowHttpLocal: true })).toBe('http://127.0.0.1:8080');
    expect(vouchOfficeOf(local('http://office.example.org'), LOCAL, { allowHttpLocal: true })).toBeNull();
  });
});
