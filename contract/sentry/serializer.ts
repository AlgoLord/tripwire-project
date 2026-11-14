import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes } from '@noble/hashes/utils';

export interface PolicyConfig {
  max_eth_transfer: string; // u128 as string
  allowed_delegates: string[];
  forbidden_spenders: string[];
}

export interface VerdictPayload {
  nonce: bigint; // u64
  payloadHash: Uint8Array; // 32 bytes
  derivationPath: string; // raw UTF-8 string
  policyHash: Uint8Array; // 32 bytes SHA-256 of PolicyConfig
}

function serializeU128(value: string): Uint8Array {
  const buf = new Uint8Array(16);
  const bigVal = BigInt(value);
  for (let i = 0; i < 16; i++) {
    buf[i] = Number((bigVal >> BigInt(i * 8)) & BigInt(0xff));
  }
  return buf;
}

function serializeString(str: string): Uint8Array {
  const strBytes = utf8ToBytes(str);
  const lenBuf = new Uint8Array(4);
  new DataView(lenBuf.buffer).setUint32(0, strBytes.length, true);
  const res = new Uint8Array(4 + strBytes.length);
  res.set(lenBuf, 0);
  res.set(strBytes, 4);
  return res;
}

function serializeStringVec(arr: string[]): Uint8Array {
  const lenBuf = new Uint8Array(4);
  new DataView(lenBuf.buffer).setUint32(0, arr.length, true);
  
  const serializedItems = arr.map(serializeString);
  const totalLen = serializedItems.reduce((acc, curr) => acc + curr.length, 4);
  
  const res = new Uint8Array(totalLen);
  res.set(lenBuf, 0);
  let offset = 4;
  for (const item of serializedItems) {
    res.set(item, offset);
    offset += item.length;
  }
  return res;
}

/**
 * Borsh serialization for PolicyConfig matching Rust struct order:
 * - max_eth_transfer: u128 (16 bytes LE)
 * - allowed_delegates: Vec<String>
 * - forbidden_spenders: Vec<String>
 */
export function serializePolicy(policy: PolicyConfig): Uint8Array {
  const maxEthBytes = serializeU128(policy.max_eth_transfer);
  const delegatesBytes = serializeStringVec(policy.allowed_delegates);
  const spendersBytes = serializeStringVec(policy.forbidden_spenders);

  const totalLen = maxEthBytes.length + delegatesBytes.length + spendersBytes.length;
  const result = new Uint8Array(totalLen);
  let offset = 0;

  result.set(maxEthBytes, offset); offset += maxEthBytes.length;
  result.set(delegatesBytes, offset); offset += delegatesBytes.length;
  result.set(spendersBytes, offset); offset += spendersBytes.length;

  return result;
}

export function hashPolicy(policy: PolicyConfig): Uint8Array {
  return sha256(serializePolicy(policy));
}

/**
 * Verdict message serialization matching Rust serialize_verdict_message:
 * nonce LE (8 bytes) || payload_hash (32 bytes) || raw UTF-8 derivation path || policy_hash (32 bytes)
 */
export function serializeVerdict(verdict: VerdictPayload): Uint8Array {
  const nonceBuf = new Uint8Array(8);
  new DataView(nonceBuf.buffer).setBigUint64(0, verdict.nonce, true);

  if (verdict.payloadHash.length !== 32) {
    throw new Error('Invalid payloadHash length: must be exactly 32 bytes');
  }

  const pathBytes = utf8ToBytes(verdict.derivationPath);

  if (verdict.policyHash.length !== 32) {
    throw new Error('Invalid policyHash length: must be exactly 32 bytes');
  }

  const totalLength = 8 + 32 + pathBytes.length + 32;
  const result = new Uint8Array(totalLength);
  let offset = 0;

  result.set(nonceBuf, offset); offset += 8;
  result.set(verdict.payloadHash, offset); offset += 32;
  result.set(pathBytes, offset); offset += pathBytes.length;
  result.set(verdict.policyHash, offset); offset += 32;

  return result;
}