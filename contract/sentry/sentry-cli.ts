import { serializeVerdict, hashPolicy, VerdictPayload, PolicyConfig } from './verifier';
import { ec as EC } from 'elliptic';

const ec = new EC('secp256k1');

export interface ContractConfig {
  verifier_pk: string;
  is_paused: boolean;
}

export async function signVerdict(
  contractConfig: ContractConfig,
  env: { SENTRY_PRIVATE_KEY?: string },
  input: {
    nonce: bigint;
    payloadHash: Uint8Array;
    derivationPath: string;
    policy: PolicyConfig;
  }
) {
  // 1. Check if contract is paused
  if (contractConfig.is_paused) {
    throw new Error('Refusing to sign: Contract is currently paused.');
  }

  // 2. Strict SENTRY_PRIVATE_KEY enforcement (no fallbacks)
  if (!env.SENTRY_PRIVATE_KEY) {
    throw new Error('Missing required environment variable: SENTRY_PRIVATE_KEY');
  }

  // 3. Strict derivation path validation (eth,<chain-id>)
  const pathRegex = /^eth,\d+$/;
  if (!pathRegex.test(input.derivationPath)) {
    throw new Error(`Invalid derivation path "${input.derivationPath}". Must follow format "eth,<chain-id>".`);
  }

  // 4. Compare derived public key against live contract verifier_pk
  const keyPair = ec.keyFromPrivate(env.SENTRY_PRIVATE_KEY, 'hex');
  const derivedPubKey = keyPair.getPublic('hex');

  if (contractConfig.verifier_pk !== derivedPubKey) {
    throw new Error(
      `Verifier key mismatch! Contract expects ${contractConfig.verifier_pk}, but private key derives ${derivedPubKey}`
    );
  }

  // 5. Build canonical verdict and sign
  const policyHash = hashPolicy(input.policy);
  const verdictPayload: VerdictPayload = {
    domain: 'TRIPWIRE_V1',
    nonce: input.nonce,
    payloadHash: input.payloadHash,
    derivationPath: input.derivationPath,
    policyHash,
  };

  const messageBytes = serializeVerdict(verdictPayload);
  const msgHash = ec.hash().update(messageBytes).digest();
  const signature = keyPair.sign(msgHash);

  return {
    signature: Buffer.from(signature.toDER()).toString('hex'),
    messageBytes: Buffer.from(messageBytes).toString('hex'),
  };
}