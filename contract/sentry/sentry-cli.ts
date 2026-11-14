import { serializeVerdict, hashPolicy, VerdictPayload, PolicyConfig, verifyEvmPayloadHash } from './verifier';
import { ec as EC } from 'elliptic';
import { hexToBytes } from '@noble/hashes/utils';

const ec = new EC('secp256k1');

export interface ContractConfig {
  verifier_pk: string;
  is_paused: boolean;
}

export async function signVerdict(
  contractConfig: ContractConfig,
  env: { SENTRY_PRIVATE_KEY?: string; SENTRY_EXPECTED_PUBLIC_KEY?: string },
  input: {
    nonce: bigint;
    payloadHashHex: string;
    derivationPath: string;
    policy: PolicyConfig;
    txFields?: any;
  }
) {
  // 1. Refuse to sign if contract is paused
  if (contractConfig.is_paused) {
    throw new Error('Refusing to sign: Contract is currently paused.');
  }

  // 2. Remove ADMIN_PRIVATE_KEY and PRIVATE_KEY fallbacks. Require SENTRY_PRIVATE_KEY exclusively.
  if (!env.SENTRY_PRIVATE_KEY) {
    throw new Error('Missing required environment variable: SENTRY_PRIVATE_KEY');
  }

  // 3. Require explicit eth,<chain-id> derivation path.
  const pathRegex = /^eth,\d+$/;
  if (!pathRegex.test(input.derivationPath)) {
    throw new Error(`Invalid derivation path "${input.derivationPath}". Must follow format "eth,<chain-id>".`);
  }

  // 4. Compare derived public key against BOTH SENTRY_EXPECTED_PUBLIC_KEY and live verifier_pk. Refuse on any mismatch.
  const keyPair = ec.keyFromPrivate(env.SENTRY_PRIVATE_KEY, 'hex');
  const derivedPubKey = keyPair.getPublic('hex');

  if (contractConfig.verifier_pk && contractConfig.verifier_pk !== derivedPubKey) {
    throw new Error(`Verifier key mismatch against contract verifier_pk: expected ${contractConfig.verifier_pk}, got ${derivedPubKey}`);
  }

  if (env.SENTRY_EXPECTED_PUBLIC_KEY && env.SENTRY_EXPECTED_PUBLIC_KEY !== derivedPubKey) {
    throw new Error(`Verifier key mismatch against SENTRY_EXPECTED_PUBLIC_KEY: expected ${env.SENTRY_EXPECTED_PUBLIC_KEY}, got ${derivedPubKey}`);
  }

  // 5. Validate payload hash and EVM transaction canonical digest
  const cleanHex = input.payloadHashHex.startsWith('0x') ? input.payloadHashHex.slice(2) : input.payloadHashHex;
  const payloadHashBytes = hexToBytes(cleanHex);
  if (payloadHashBytes.length !== 32) {
    throw new Error('Invalid payloadHash length: must be exactly 32 bytes');
  }

  if (input.txFields) {
    const isValidTx = verifyEvmPayloadHash(input.txFields, input.payloadHashHex);
    if (!isValidTx) {
      throw new Error('EVM transaction payload hash verification failed');
    }
  }

  // 6. Build canonical verdict and sign exact message bytes matching Rust
  const policyHash = hashPolicy(input.policy);
  const verdictPayload: VerdictPayload = {
    domain: 'TRIPWIRE_V1',
    nonce: input.nonce,
    payloadHash: payloadHashBytes,
    derivationPath: input.derivationPath,
    policyHash,
  };

  const messageBytes = serializeVerdict(verdictPayload);
  const msgHash = ec.hash().update(messageBytes).digest();
  const signature = keyPair.sign(msgHash);

  return {
    signature: Buffer.from(signature.toDER()).toString('hex'),
    messageBytes: Buffer.from(messageBytes).toString('hex'),
    policyHashHex: Buffer.from(policyHash).toString('hex'),
  };
}

if (require.main === module) {
  console.log('Tripwire Sentry CLI loaded successfully.');
}