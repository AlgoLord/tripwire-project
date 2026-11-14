import { serializeVerdict, hashPolicy, VerdictPayload, PolicyConfig } from './serializer';
import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes, hexToBytes } from '@noble/hashes/utils';
import { ec as EC } from 'elliptic';

const ec = new EC('secp256k1');

export interface ContractConfig {
  verifier_pk: string;
  is_paused: boolean;
}

export function verifyEvmPayloadHash(
  txFields: { nonce: number; gasPrice?: string; maxFeePerGas?: string; to: string; value: string; data?: string; chainId: number },
  payloadHashHex: string
): boolean {
  if (!txFields.to || !txFields.value || txFields.nonce === undefined) {
    throw new Error('Rejecting malformed EVM transaction: missing required fields');
  }
  if (!payloadHashHex || typeof payloadHashHex !== 'string') {
    throw new Error('Rejecting malformed payload hash');
  }

  const canonicalString = JSON.stringify({
    nonce: txFields.nonce,
    gasPrice: txFields.gasPrice || txFields.maxFeePerGas || '0',
    to: txFields.to,
    value: txFields.value,
    data: txFields.data || '0x',
    chainId: txFields.chainId,
  });

  const computedHash = sha256(utf8ToBytes(canonicalString));
  const cleanHex = payloadHashHex.startsWith('0x') ? payloadHashHex.slice(2) : payloadHashHex;
  const expectedBytes = hexToBytes(cleanHex);

  if (computedHash.length !== expectedBytes.length) return false;
  return computedHash.every((val, idx) => val === expectedBytes[idx]);
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

  // 2. Remove ADMIN_PRIVATE_KEY / PRIVATE_KEY fallbacks. Require SENTRY_PRIVATE_KEY exclusively.
  if (!env.SENTRY_PRIVATE_KEY) {
    throw new Error('Missing required environment variable: SENTRY_PRIVATE_KEY');
  }

  // 3. Require explicit eth,<chain-id> derivation path. Reject NEAR defaults.
  const pathRegex = /^eth,\d+$/;
  if (!pathRegex.test(input.derivationPath)) {
    throw new Error(`Invalid derivation path "${input.derivationPath}". Must be explicit format "eth,<chain-id>".`);
  }

  // 4. Compare derived public key against BOTH verifier_pk and SENTRY_EXPECTED_PUBLIC_KEY
  const keyPair = ec.keyFromPrivate(env.SENTRY_PRIVATE_KEY, 'hex');
  const derivedPubKey = keyPair.getPublic('hex');

  if (contractConfig.verifier_pk && contractConfig.verifier_pk !== derivedPubKey) {
    throw new Error(`Verifier key mismatch against contract verifier_pk: expected ${contractConfig.verifier_pk}, got ${derivedPubKey}`);
  }

  if (env.SENTRY_EXPECTED_PUBLIC_KEY && env.SENTRY_EXPECTED_PUBLIC_KEY !== derivedPubKey) {
    throw new Error(`Verifier key mismatch against SENTRY_EXPECTED_PUBLIC_KEY: expected ${env.SENTRY_EXPECTED_PUBLIC_KEY}, got ${derivedPubKey}`);
  }

  // 5. Verify payload hash and EVM transaction fields if provided
  const cleanHex = input.payloadHashHex.startsWith('0x') ? input.payloadHashHex.slice(2) : input.payloadHashHex;
  const payloadHashBytes = hexToBytes(cleanHex);
  if (payloadHashBytes.length !== 32) {
    throw new Error('Invalid payloadHash length: must be 32 bytes');
  }

  if (input.txFields) {
    const isValidTx = verifyEvmPayloadHash(input.txFields, input.payloadHashHex);
    if (!isValidTx) {
      throw new Error('EVM transaction payload hash verification failed');
    }
  }

  // 6. Build canonical verdict and sign exact Rust-compatible message bytes
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