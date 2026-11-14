import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils';
import { serializeVerdict, hashPolicy, PolicyConfig } from './serializer';
import { verifyEvmPayloadHash, EvmTxFields } from './verifier';
import * as dotenv from 'dotenv';

dotenv.config();

// Configure ed25519 sha512 sync implementation
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

export interface ContractConfig {
  verifier_pk: string; // ed25519 public key (hex or ed25519:... format)
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
    txFields: EvmTxFields; // Mandatory
  }
) {
  // 1. Check pause state
  if (contractConfig.is_paused) {
    throw new Error('Refusing to sign: Contract is currently paused.');
  }

  // 2. Enforce strict SENTRY_PRIVATE_KEY (no fallback)
  if (!env.SENTRY_PRIVATE_KEY) {
    throw new Error('Missing required environment variable: SENTRY_PRIVATE_KEY');
  }

  // 3. Enforce strict SENTRY_EXPECTED_PUBLIC_KEY
  if (!env.SENTRY_EXPECTED_PUBLIC_KEY) {
    throw new Error('Missing required environment variable: SENTRY_EXPECTED_PUBLIC_KEY');
  }

  // 4. Require explicit eth,<chain-id> derivation path
  const pathRegex = /^eth,\d+$/;
  if (!pathRegex.test(input.derivationPath)) {
    throw new Error(`Invalid derivation path "${input.derivationPath}". Must be explicit "eth,<chain-id>".`);
  }

  // 5. Derive Ed25519 public key from private key
  const cleanPrivKey = env.SENTRY_PRIVATE_KEY.startsWith('ed25519:')
    ? env.SENTRY_PRIVATE_KEY.slice(8)
    : env.SENTRY_PRIVATE_KEY;
  const privBytes = hexToBytes(cleanPrivKey);
  const derivedPubKeyBytes = await ed.getPublicKey(privBytes);
  const derivedPubKeyHex = bytesToHex(derivedPubKeyBytes);

  // 6. Compare derived public key against BOTH SENTRY_EXPECTED_PUBLIC_KEY and contract verifier_pk
  const cleanExpectedPub = env.SENTRY_EXPECTED_PUBLIC_KEY.startsWith('ed25519:')
    ? env.SENTRY_EXPECTED_PUBLIC_KEY.slice(8)
    : env.SENTRY_EXPECTED_PUBLIC_KEY;
  const cleanContractPub = contractConfig.verifier_pk.startsWith('ed25519:')
    ? contractConfig.verifier_pk.slice(8)
    : contractConfig.verifier_pk;

  if (derivedPubKeyHex !== cleanExpectedPub) {
    throw new Error(`Verifier public key mismatch against SENTRY_EXPECTED_PUBLIC_KEY: expected ${cleanExpectedPub}, got ${derivedPubKeyHex}`);
  }

  if (cleanContractPub && derivedPubKeyHex !== cleanContractPub) {
    throw new Error(`Verifier public key mismatch against live contract verifier_pk: expected ${cleanContractPub}, got ${derivedPubKeyHex}`);
  }

  // 7. Make txFields mandatory and verify EVM transaction digest
  if (!input.txFields) {
    throw new Error('Refusing to sign: txFields is mandatory and must not be skipped.');
  }
  const isValidTx = verifyEvmPayloadHash(input.txFields, input.payloadHashHex);
  if (!isValidTx) {
    throw new Error('EVM transaction canonical digest verification failed against payloadHashHex.');
  }

  // 8. Serialize policy, hash, and build exact Rust-compatible verdict message
  const policyHash = hashPolicy(input.policy);
  const verdictPayload = {
    nonce: input.nonce,
    payloadHash: hexToBytes(input.payloadHashHex.startsWith('0x') ? input.payloadHashHex.slice(2) : input.payloadHashHex),
    derivationPath: input.derivationPath,
    policyHash,
  };

  const messageBytes = serializeVerdict(verdictPayload);
  
  // 9. Produce 64-byte Ed25519 signature expected by Rust env::ed25519_verify
  const signatureBytes = await ed.signAsync(messageBytes, privBytes);

  return {
    signature: bytesToHex(signatureBytes),
    messageBytes: bytesToHex(messageBytes),
    policyHashHex: bytesToHex(policyHash),
  };
}

// Execute CLI when run directly via npm run sign
if (require.main === module) {
  (async () => {
    try {
      console.log('Executing Tripwire Sentry CLI...');
      const mockConfig: ContractConfig = {
        verifier_pk: process.env.SENTRY_EXPECTED_PUBLIC_KEY || '',
        is_paused: false,
      };
      const mockPolicy: PolicyConfig = {
        max_eth_transfer: '1000000000000000000',
        allowed_delegates: [],
        forbidden_spenders: [],
      };
      const mockTx = { type: 0, nonce: 0, gasPrice: '20000000000', gasLimit: '21000', to: '0x1234567890abcdef1234567890abcdef12345678', value: '100', chainId: 1, data: '0x' };
      const dummyHash = '0x' + Buffer.from(require('./verifier').computeEvmTransactionDigest(mockTx)).toString('hex');

      const result = await signVerdict(
        mockConfig,
        {
          SENTRY_PRIVATE_KEY: process.env.SENTRY_PRIVATE_KEY,
          SENTRY_EXPECTED_PUBLIC_KEY: process.env.SENTRY_EXPECTED_PUBLIC_KEY,
        },
        {
          nonce: 1n,
          payloadHashHex: dummyHash,
          derivationPath: 'eth,1',
          policy: mockPolicy,
          txFields: mockTx,
        }
      );
      console.log('Signature generated successfully:', result);
    } catch (err: any) {
      console.error('CLI signing failed:', err.message);
      process.exit(1);
    }
  })();
}