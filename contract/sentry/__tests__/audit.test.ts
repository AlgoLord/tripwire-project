import { serializePolicy, hashPolicy, serializeVerdict } from '../serializer';
import { validateAndSign } from '../cli';

describe('Tripwire Sentry Audit Test Suite', () => {
  const mockPolicy = { max_amount: '1000000000000000000', to_address: '0x1234...5678' };
  const dummyPrivateKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  const dummyPubKey = '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';

  test('Policy serialization is deterministic and matches Borsh format', () => {
    const serialized1 = serializePolicy(mockPolicy);
    const serialized2 = serializePolicy(mockPolicy);
    expect(serialized1).toEqual(serialized2);
    expect(serialized1.length).toBe(20 + mockPolicy.to_address.length);
  });

  test('Rejects invalid derivation paths missing eth prefix', async () => {
    await expect(
      validateAndSign(
        { verifier_pk: dummyPubKey, is_paused: false },
        { SENTRY_PRIVATE_KEY: dummyPrivateKey },
        { nonce: 1n, payloadHash: new Uint8Array(32), derivationPath: 'near,v3.tripwire-admin.testnet', policy: mockPolicy }
      )
    ).rejects.toThrow(/Invalid derivation path/);
  });

  test('Refuses to sign when contract is paused', async () => {
    await expect(
      validateAndSign(
        { verifier_pk: dummyPubKey, is_paused: true },
        { SENTRY_PRIVATE_KEY: dummyPrivateKey },
        { nonce: 1n, payloadHash: new Uint8Array(32), derivationPath: 'eth,1', policy: mockPolicy }
      )
    ).rejects.toThrow(/Contract is currently paused/);
  });
});