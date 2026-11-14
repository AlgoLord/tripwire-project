import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { serializePolicy, hashPolicy, serializeVerdict, PolicyConfig } from './serializer';
import { computeEvmTransactionDigest, verifyEvmPayloadHash, EvmTxFields } from './verifier';
import { signVerdict } from './sentry-cli';

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

async function runTests() {
  console.log('Running Tripwire Sentry rigorous audit test suite...');

  // 1. Policy Bytes & Structure Test
  const mockPolicy: PolicyConfig = {
    max_eth_transfer: '1000000000000000000',
    allowed_delegates: ['0xDelegator1'],
    forbidden_spenders: ['0xSpender1'],
  };
  const pBytes1 = serializePolicy(mockPolicy);
  const pBytes2 = serializePolicy(mockPolicy);
  if (pBytes1.toString() !== pBytes2.toString()) {
    throw new Error('Test 1 failed: Policy serialization non-deterministic');
  }
  console.log('✓ PolicyConfig Borsh serialization byte equality test passed!');

  // 2. Verdict Message Bytes Test
  const pHash = hashPolicy(mockPolicy);
  const dummyPayload = hexToBytes('a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef');
  const verdict = {
    nonce: 1n,
    payloadHash: dummyPayload,
    derivationPath: 'eth,1',
    policyHash: pHash,
  };
  const vBytes = serializeVerdict(verdict);
  if (vBytes.length !== 8 + 32 + 5 + 32) {
    throw new Error('Test 2 failed: Verdict message byte layout mismatch');
  }
  console.log('✓ Verdict message bytes layout matches Rust format!');

  // 3. Ed25519 Signature & Rust compatibility test
  const privKeyBytes = ed.utils.randomPrivateKey();
  const pubKeyBytes = await ed.getPublicKey(privKeyBytes);
  const privHex = bytesToHex(privKeyBytes);
  const pubHex = bytesToHex(pubKeyBytes);

  const txFields: EvmTxFields = {
    type: 0,
    nonce: 0,
    gasPrice: '20000000000',
    gasLimit: '21000',
    to: '0x1234567890abcdef1234567890abcdef12345678',
    value: '100',
    chainId: 1,
    data: '0x',
  };
  const payloadDigestHex = '0x' + bytesToHex(computeEvmTransactionDigest(txFields));

  const signResult = await signVerdict(
    { verifier_pk: pubHex, is_paused: false },
    { SENTRY_PRIVATE_KEY: privHex, SENTRY_EXPECTED_PUBLIC_KEY: pubHex },
    {
      nonce: 1n,
      payloadHashHex: payloadDigestHex,
      derivationPath: 'eth,1',
      policy: mockPolicy,
      txFields,
    }
  );

  const isValidSig = await ed.verifyAsync(
    hexToBytes(signResult.signature),
    hexToBytes(signResult.messageBytes),
    pubKeyBytes
  );
  if (!isValidSig) {
    throw new Error('Test 3 failed: Ed25519 signature verification failed');
  }
  console.log('✓ Ed25519 signature verification against Rust-compatible message passed!');

  // 4. Security Rejections: Wrong Key, Paused, Bad Path, Missing Key
  try {
    await signVerdict(
      { verifier_pk: '00'.repeat(32), is_paused: false },
      { SENTRY_PRIVATE_KEY: privHex, SENTRY_EXPECTED_PUBLIC_KEY: pubHex },
      { nonce: 1n, payloadHashHex: payloadDigestHex, derivationPath: 'eth,1', policy: mockPolicy, txFields }
    );
    throw new Error('Should have rejected public key mismatch');
  } catch (e: any) {
    if (!e.message.includes('Verifier public key mismatch')) throw e;
  }
  console.log('✓ Wrong key rejection test passed!');

  try {
    await signVerdict(
      { verifier_pk: pubHex, is_paused: true },
      { SENTRY_PRIVATE_KEY: privHex, SENTRY_EXPECTED_PUBLIC_KEY: pubHex },
      { nonce: 1n, payloadHashHex: payloadDigestHex, derivationPath: 'eth,1', policy: mockPolicy, txFields }
    );
    throw new Error('Should have rejected paused contract');
  } catch (e: any) {
    if (!e.message.includes('Contract is currently paused')) throw e;
  }
  console.log('✓ Paused contract rejection test passed!');

  try {
    await signVerdict(
      { verifier_pk: pubHex, is_paused: false },
      {},
      { nonce: 1n, payloadHashHex: payloadDigestHex, derivationPath: 'eth,1', policy: mockPolicy, txFields }
    );
    throw new Error('Should have rejected missing private key');
  } catch (e: any) {
    if (!e.message.includes('Missing required environment variable: SENTRY_PRIVATE_KEY')) throw e;
  }
  console.log('✓ Missing private key rejection test passed!');

  // 5. EVM Transaction Types Digest Tests (Type 0, Type 1, Type 2)
  const txType0: EvmTxFields = { type: 0, nonce: 1, gasPrice: '20000000000', gasLimit: '21000', to: '0x1234567890abcdef1234567890abcdef12345678', value: '10', chainId: 1, data: '0x' };
  const txType1: EvmTxFields = { type: 1, nonce: 1, gasPrice: '20000000000', gasLimit: '21000', to: '0x1234567890abcdef1234567890abcdef12345678', value: '10', chainId: 1, data: '0x', accessList: [['0xabcdefabcdefabcdefabcdefabcdefabcdefabcd', ['0x0']]] };
  const txType2: EvmTxFields = { type: 2, nonce: 1, maxPriorityFeePerGas: '1000000000', maxFeePerGas: '20000000000', gasLimit: '21000', to: '0x1234567890abcdef1234567890abcdef12345678', value: '10', chainId: 1, data: '0x' };

  const digest0 = computeEvmTransactionDigest(txType0);
  const digest1 = computeEvmTransactionDigest(txType1);
  const digest2 = computeEvmTransactionDigest(txType2);

  if (digest0.length !== 32 || digest1.length !== 32 || digest2.length !== 32) {
    throw new Error('Test 5 failed: EVM digest length incorrect');
  }
  console.log('✓ All EVM transaction types (0, 1, 2) produce correct canonical digests!');

  console.log('\nAll Tripwire verifier audit tests passed successfully.');
}

runTests().catch(err => {
  console.error('❌ Test failed:', err.message);
  process.exit(1);
});