/**
 * Random Universe Cipher - SHAKE256 Wrapper
 * 
 * Wrapper around @noble/hashes for SHAKE256 operations
 */

import { shake256 } from '@noble/hashes/sha3';
import { concatBytes, stringToBytes, numberToBytes } from './bigint-utils';

/**
 * Compute SHAKE256 hash with arbitrary output length
 */
export function shake256Hash(data: Uint8Array, outputLength: number): Uint8Array {
  return shake256(data, { dkLen: outputLength });
}

/**
 * Compute SHAKE256 with domain separation
 * Format: key || domain || index_bytes
 */
export function shake256WithDomain(
  key: Uint8Array,
  domain: string,
  index: number,
  outputLength: number
): Uint8Array {
  const domainBytes = stringToBytes(domain);
  const indexBytes = numberToBytes(index, 2); // 2-byte index
  const input = concatBytes(key, domainBytes, indexBytes);
  return shake256(input, { dkLen: outputLength });
}

/**
 * Compute SHAKE256 with domain separation and bigint index
 */
export function shake256WithDomainBigInt(
  key: Uint8Array,
  domain: string,
  index: bigint,
  outputLength: number
): Uint8Array {
  const domainBytes = stringToBytes(domain);
  // Convert bigint to 8-byte big-endian
  const indexBytes = new Uint8Array(8);
  let value = index;
  for (let i = 7; i >= 0; i--) {
    indexBytes[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  const input = concatBytes(key, domainBytes, indexBytes);
  return shake256(input, { dkLen: outputLength });
}

/**
 * Compute SHAKE256 with multiple components concatenated
 */
export function shake256Multi(components: Uint8Array[], outputLength: number): Uint8Array {
  const input = concatBytes(...components);
  return shake256(input, { dkLen: outputLength });
}

/**
 * Derive a key using SHAKE256 (simple KDF)
 * For production, use proper KDF like Argon2
 */
export function deriveKey(
  password: string | Uint8Array,
  salt: Uint8Array,
  outputLength: number
): Uint8Array {
  const passwordBytes = typeof password === 'string' 
    ? stringToBytes(password) 
    : password;
  const input = concatBytes(passwordBytes, salt);
  return shake256(input, { dkLen: outputLength });
}

