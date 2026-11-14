import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes } from '@noble/hashes/utils';

export interface PolicyConfig {
  max_amount: string; // u128 as string
  to_address: string;
}

export interface VerdictPayload {
  domain: string; // "TRIPWIRE_V1"
  nonce: bigint; // u64
  payloadHash: Uint8Array; // 32 bytes
  derivationPath: string; // e.g., "eth,1"
  policyHash: Uint8Array; // 32 bytes SHA-256 of policy config
}

export function serializePolicy(policy: PolicyConfig): Uint8Array {
  // Simple deterministic Borsh serialization for PolicyConfig
  // u128 max_amount (16 bytes LE) + string to_address (4 bytes len + utf8)
  const amountBuf = new Uint8Array(16);
  const amtBig = BigInt(policy.max_amount);
  for (let i = 0; i < 16; i++) {
    amountBuf[i] = Number((amtBig >> BigInt(i * 8)) & BigInt(0xff));
  }
  const addrBytes = utf8ToBytes(policy.to_address);
  const addrLenBuf = new Uint8Array(4);
  new DataView(addrLenBuf.buffer).setUint32(0, addrBytes.length, true);

  const combined = new Uint8Array(16 + 4 + addrBytes.length);
  combined.set(amountBuf, 0);
  combined.set(addrLenBuf, 16);
  combined.set(addrBytes, 20);
  return combined;
}

export function hashPolicy(policy: PolicyConfig): Uint8Array {
  return sha256(serializePolicy(policy));
}

export function serializeVerdict(verdict: VerdictPayload): Uint8Array {
  const domainBytes = utf8ToBytes(verdict.domain);
  const domainLen = new Uint8Array(4);
  new DataView(domainLen.buffer).setUint32(0, domainBytes.length, true);

  // Nonce: 8 bytes LE (u64)
  const nonceBuf = new Uint8Array(8);
  new DataView(nonceBuf.buffer).setBigUint64(0, verdict.nonce, true);

  // Derivation path string
  const pathBytes = utf8ToBytes(verdict.derivationPath);
  const pathLen = new Uint8Array(4);
  new DataView(pathLen.buffer).setUint32(0, pathBytes.length, true);

  // Concatenate components in canonical Borsh order
  const totalLength =
    4 + domainBytes.length +
    8 +
    32 + // payloadHash
    4 + pathBytes.length +
    32;  // policyHash

  const result = new Uint8Array(totalLength);
  let offset = 0;

  result.set(domainLen, offset); offset += 4;
  result.set(domainBytes, offset); offset += domainBytes.length;
  result.set(nonceBuf, offset); offset += 8;
  result.set(verdict.payloadHash, offset); offset += 32;
  result.set(pathLen, offset); offset += 4;
  result.set(pathBytes, offset); offset += pathBytes.length;
  result.set(verdict.policyHash, offset); offset += 32;

  return result;
}