import { keccak_256 } from '@noble/hashes/sha3';
import { hexToBytes } from '@noble/hashes/utils';

export interface EvmTxFields {
  type?: number; // 0, 1, or 2
  nonce: number | bigint | string;
  gasPrice?: string | bigint | number;
  maxPriorityFeePerGas?: string | bigint | number;
  maxFeePerGas?: string | bigint | number;
  gasLimit: string | bigint | number;
  to: string; // 0x hex address
  value: string | bigint | number;
  data: string; // 0x hex data
  chainId: number | bigint | string;
  accessList?: Array<[string, string[]]>;
}

function rlpEncodeLength(length: number, offset: number): Uint8Array {
  if (length < 56) {
    return new Uint8Array([length + offset]);
  } else {
    const hexString = length.toString(16);
    const lenBytes = hexToBytes(hexString.length % 2 === 0 ? hexString : '0' + hexString);
    const res = new Uint8Array(1 + lenBytes.length);
    res[0] = offset + 56 + lenBytes.length - 1;
    res.set(lenBytes, 1);
    return res;
  }
}

function rlpEncodeItem(input: Uint8Array | Uint8Array[]): Uint8Array {
  if (Array.isArray(input)) {
    let payloadLen = 0;
    for (const item of input) {
      payloadLen += item.length;
    }
    const header = rlpEncodeLength(payloadLen, 192);
    const res = new Uint8Array(header.length + payloadLen);
    res.set(header, 0);
    let offset = header.length;
    for (const item of input) {
      res.set(item, offset);
      offset += item.length;
    }
    return res;
  } else {
    if (input.length === 1 && input[0] < 128) {
      return input;
    } else {
      const header = rlpEncodeLength(input.length, 128);
      const res = new Uint8Array(header.length + input.length);
      res.set(header, 0);
      res.set(input, header.length);
      return res;
    }
  }
}

function numberToBytes(num: number | bigint | string | undefined): Uint8Array {
  if (num === undefined || num === null || num === 0 || num === 0n || num === '0' || num === '0x0') {
    return new Uint8Array(0);
  }
  let bigVal: bigint;
  if (typeof num === 'string') {
    bigVal = num.startsWith('0x') ? BigInt(num) : BigInt(num);
  } else {
    bigVal = BigInt(num);
  }
  if (bigVal === 0n) return new Uint8Array(0);
  let hex = bigVal.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  return hexToBytes(hex);
}

function addressToBytes(addr: string): Uint8Array {
  const clean = addr.startsWith('0x') ? addr.slice(2) : addr;
  return hexToBytes(clean);
}

function dataToBytes(data: string): Uint8Array {
  if (!data || data === '0x') return new Uint8Array(0);
  const clean = data.startsWith('0x') ? data.slice(2) : data;
  return hexToBytes(clean);
}

/**
 * Computes canonical Keccak-256 EVM signing digest for Type 0, 1, and 2 transactions.
 */
export function computeEvmTransactionDigest(tx: EvmTxFields): Uint8Array {
  if (!tx || tx.nonce === undefined || !tx.to || tx.value === undefined || tx.chainId === undefined) {
    throw new Error('Mandatory transaction fields missing for EVM digest verification.');
  }

  const txType = tx.type ?? 0;

  if (txType === 0) {
    const items = [
      numberToBytes(tx.nonce),
      numberToBytes(tx.gasPrice || 0n),
      numberToBytes(tx.gasLimit),
      addressToBytes(tx.to),
      numberToBytes(tx.value),
      dataToBytes(tx.data),
      numberToBytes(tx.chainId),
      new Uint8Array(0),
      new Uint8Array(0),
    ];
    const encoded = rlpEncodeItem(items);
    return keccak_256(encoded);
  } else if (txType === 1) {
    const encodedList = (tx.accessList || []).map(([addr, storageKeys]) => [
      addressToBytes(addr),
      storageKeys.map(k => hexToBytes(k.startsWith('0x') ? k.slice(2) : k))
    ]);
    const items = [
      numberToBytes(tx.chainId),
      numberToBytes(tx.nonce),
      numberToBytes(tx.gasPrice || 0n),
      numberToBytes(tx.gasLimit),
      addressToBytes(tx.to),
      numberToBytes(tx.value),
      dataToBytes(tx.data),
      encodedList as any,
    ];
    const rlpEncoded = rlpEncodeItem(items);
    const payload = new Uint8Array(1 + rlpEncoded.length);
    payload[0] = 1;
    payload.set(rlpEncoded, 1);
    return keccak_256(payload);
  } else if (txType === 2) {
    const encodedList = (tx.accessList || []).map(([addr, storageKeys]) => [
      addressToBytes(addr),
      storageKeys.map(k => hexToBytes(k.startsWith('0x') ? k.slice(2) : k))
    ]);
    const items = [
      numberToBytes(tx.chainId),
      numberToBytes(tx.nonce),
      numberToBytes(tx.maxPriorityFeePerGas || 0n),
      numberToBytes(tx.maxFeePerGas || 0n),
      numberToBytes(tx.gasLimit),
      addressToBytes(tx.to),
      numberToBytes(tx.value),
      dataToBytes(tx.data),
      encodedList as any,
    ];
    const rlpEncoded = rlpEncodeItem(items);
    const payload = new Uint8Array(1 + rlpEncoded.length);
    payload[0] = 2;
    payload.set(rlpEncoded, 1);
    return keccak_256(payload);
  } else {
    throw new Error(`Unsupported transaction type: ${txType}`);
  }
}

export function verifyEvmPayloadHash(txFields: EvmTxFields, payloadHashHex: string): boolean {
  if (!txFields) {
    throw new Error('txFields is mandatory for payload hash verification.');
  }
  if (!payloadHashHex || typeof payloadHashHex !== 'string') {
    throw new Error('Invalid payload hash format.');
  }

  const computedDigest = computeEvmTransactionDigest(txFields);
  const cleanHex = payloadHashHex.startsWith('0x') ? payloadHashHex.slice(2) : payloadHashHex;
  const expectedBytes = hexToBytes(cleanHex);

  if (computedDigest.length !== expectedBytes.length) return false;
  return computedDigest.every((val, idx) => val === expectedBytes[idx]);
}