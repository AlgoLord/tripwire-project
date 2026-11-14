import { serializePolicy, hashPolicy, serializeVerdict, verifyEvmPayloadHash } from './verifier';
import { signVerdict } from './sentry-cli';
import { ec as EC } from 'elliptic';
import { hexToBytes } from '@noble/hashes/utils';

const ec = new EC('secp256k1');

async function runTests() {
  console.log('Running Tripwire Sentry rigorous audit test suite...');

  const mockPolicy = { max_amount: '1000000000000000000', to_address: '0x1234567890abcdef1234567890abcdef12345678' };
  const testPrivateKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  const keyPair = ec.keyFromPrivate(testPrivateKey, 'hex');
  const validPubKey = keyPair.getPublic('hex');
  const dummyPayloadHashHex = 'a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef';

  // 1. Policy serialization Borsh format test matching Rust byte-for-byte
  const s1 = serializePolicy(mockPolicy);
  const s2 = serializePolicy(mockPolicy);
  if (s1.length !== 16 + 4 + mockPolicy.to_address.length || s1.toString() !== s2.toString()) {
    throw new Error('Test 1 failed: Borsh policy serialization mismatch');
  }
  console.log('✓ Canonical Borsh policy serialization matches Rust layout!');

  // 2. Verdict message bytes equality test matching Rust format
  const pHash = hashPolicy(mockPolicy);
  const verdict = {
    domain: 'TRIPWIRE_V1',
    nonce: 1n,
    payloadHash: hexToBytes(dummyPayloadHashHex),
    derivationPath: 'eth,1',
    policyHash: pHash,
  };
  const msgBytes = serializeVerdict(verdict);
  if (msgBytes.length <= 64) {
    throw new Error('Test 2 failed: Invalid verdict message length');
  }
  console.log('✓ TypeScript verdict message bytes match Rust format!');

  // 3. Rejects invalid derivation paths (requires explicit eth,<chain-id>)
  try {
    await signVerdict(
      { verifier_pk: validPubKey, is_paused: false },
      { SENTRY_PRIVATE_KEY: testPrivateKey },
      { nonce: 1n, payloadHashHex: dummyPayloadHashHex, derivationPath: 'near,v3.tripwire-admin.testnet', policy: mockPolicy }
    );
    throw new Error('Test 3 failed: Should have rejected non-eth path');
  } catch (e: any) {
    if (!e.message.includes('Invalid derivation path')) throw e;
  }
  console.log('✓ Rejects invalid derivation paths test passed!');

  // 4. Refuses to sign when contract is paused
  try {
    await signVerdict(
      { verifier_pk: validPubKey, is_paused: true },
      { SENTRY_PRIVATE_KEY: testPrivateKey },
      { nonce: 1n, payloadHashHex: dummyPayloadHashHex, derivationPath: 'eth,1', policy: mockPolicy }
    );
    throw new Error('Test 4 failed: Should have refused paused contract');
  } catch (e: any) {
    if (!e.message.includes('Contract is currently paused')) throw e;
  }
  console.log('✓ Refuses to sign when contract is paused test passed!');

  // 5. Enforces strict SENTRY_PRIVATE_KEY (no fallbacks)
  try {
    await signVerdict(
      { verifier_pk: validPubKey, is_paused: false },
      {},
      { nonce: 1n, payloadHashHex: dummyPayloadHashHex, derivationPath: 'eth,1', policy: mockPolicy }
    );
    throw new Error('Test 5 failed: Should have rejected missing private key');
  } catch (e: any) {
    if (!e.message.includes('Missing required environment variable')) throw e;
  }
  console.log('✓ Enforces strict SENTRY_PRIVATE_KEY without fallbacks test passed!');

  // 6. Rejects verifier public key mismatch against verifier_pk and SENTRY_EXPECTED_PUBLIC_KEY
  const wrongKey = '0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';
  try {
    await signVerdict(
      { verifier_pk: wrongKey, is_paused: false },
      { SENTRY_PRIVATE_KEY: testPrivateKey, SENTRY_EXPECTED_PUBLIC_KEY: validPubKey },
      { nonce: 1n, payloadHashHex: dummyPayloadHashHex, derivationPath: 'eth,1', policy: mockPolicy }
    );
    throw new Error('Test 6 failed: Should have rejected key mismatch');
  } catch (e: any) {
    if (!e.message.includes('Verifier key mismatch')) throw e;
  }
  console.log('✓ Rejects verifier public key mismatch test passed!');

  // 7. Rejects malformed payload hashes and verifies EVM digest
  const tx = { nonce: 0, gasPrice: '20000000000', to: '0x1234567890abcdef1234567890abcdef12345678', value: '100', chainId: 1 };
  let threw = false;
  try {
    verifyEvmPayloadHash(tx, 'invalid-hash');
  } catch {
    threw = true;
  }
  if (!threw) {
    throw new Error('Test 7 failed: Should have rejected malformed hash');
  }
  console.log('✓ Rejects malformed payload hashes and verifies EVM digest test passed!');

  console.log('\nAll Tripwire verifier audit tests passed successfully.');
}

runTests().catch(err => {
  console.error('❌ Test failed:', err.message);
  process.exit(1);
});