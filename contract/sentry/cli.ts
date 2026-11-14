import { serializeVerdict, hashPolicy, VerdictPayload } from './serializer';
import { ec as EC } from 'elliptic';

const ec = new EC('secp256k1');

export async function validateAndSign(
  contractConfig: { verifier_pk: string; is_paused: boolean },
  env: { SENTRY_PRIVATE_KEY?: string; SENTRY_EXPECTED_PUBLIC_KEY?: string },
  input: {
    nonce: bigint;
    payloadHash: Uint8Array;
    derivationPath: string;
    policy: { max_amount: string; to_address: string };
  }
) {
  // 1. Refuse to sign if the contract is paused
  if (contractConfig.is_paused) {
    throw new Error('Refusing to sign: Contract is currently paused.');
  }

  // 2. Enforce strict SENTRY_PRIVATE_KEY presence (no insecure fallbacks)
  if (!env.SENTRY_PRIVATE_KEY) {
    throw new Error('Missing required environment variable: SENTRY_PRIVATE_KEY');
  }

  // 3. Validate strict derivation path format (Must be eth,<chain-id>)
  const pathRegex = /^eth,\d+$/;
  if (!pathRegex.test(input.derivationPath)) {
    throw new Error(`Invalid derivation path "${input.derivationPath}". Must follow format "eth,<chain-id>".`);
  }

  // 4. Derive public key and compare against live contract config verifier_pk
  const keyPair = ec.keyFromPrivate(env.SENTRY_PRIVATE_KEY, 'hex');
  const derivedPubKey = keyPair.getPublic('hex');

  if (contractConfig.verifier_pk !== derivedPubKey) {
    throw new Error(
      `Verifier key mismatch! Contract expects ${contractConfig.verifier_pk}, but private key derives ${derivedPubKey}`
    );
  }

  if (env.SENTRY_EXPECTED_PUBLIC_KEY && env.SENTRY_EXPECTED_PUBLIC_KEY !== derivedPubKey) {
    throw new Error('SENTRY_EXPECTED_PUBLIC_KEY does not match derived public key.');
  }

  // 5. Build canonical verdict and sign using secp256k1
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