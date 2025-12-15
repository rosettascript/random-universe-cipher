/**
 * Random Universe Cipher - BigInt Utilities
 * 
 * Helper functions for 512-bit and 1024-bit integer operations
 * using native JavaScript BigInt
 */

import { MASK } from './constants';

/**
 * Convert a Uint8Array to a BigInt (big-endian)
 */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/**
 * Convert a BigInt to a Uint8Array of specified length (big-endian)
 */
export function bigIntToBytes(n: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  let value = n;
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}

/**
 * Rotate a 512-bit value left by n bits
 */
export function rotateLeft512(x: bigint, n: number): bigint {
  n = n % 512;
  if (n === 0) return x & MASK.U512;
  const left = (x << BigInt(n)) & MASK.U512;
  const right = (x >> BigInt(512 - n)) & MASK.U512;
  return left | right;
}

/**
 * Rotate a 512-bit value right by n bits
 */
export function rotateRight512(x: bigint, n: number): bigint {
  n = n % 512;
  if (n === 0) return x & MASK.U512;
  const right = (x >> BigInt(n)) & MASK.U512;
  const left = (x << BigInt(512 - n)) & MASK.U512;
  return left | right;
}

/**
 * XOR two 512-bit values
 */
export function xor512(a: bigint, b: bigint): bigint {
  return (a ^ b) & MASK.U512;
}

/**
 * XOR two 1024-bit values
 */
export function xor1024(a: bigint, b: bigint): bigint {
  return (a ^ b) & MASK.U1024;
}

/**
 * Add two 1024-bit values (modular addition)
 */
export function add1024(a: bigint, b: bigint): bigint {
  return (a + b) & MASK.U1024;
}

/**
 * Extract a byte from a bigint at a specific position (0 = most significant)
 */
export function extractByte(value: bigint, byteIndex: number, totalBytes: number): number {
  const shift = BigInt((totalBytes - 1 - byteIndex) * 8);
  return Number((value >> shift) & 0xffn);
}

/**
 * Set a byte in a bigint at a specific position (0 = most significant)
 */
export function setByte(value: bigint, byteIndex: number, byteValue: number, totalBytes: number): bigint {
  const shift = BigInt((totalBytes - 1 - byteIndex) * 8);
  const mask = ~(0xffn << shift);
  return (value & mask) | (BigInt(byteValue) << shift);
}

/**
 * Concatenate multiple Uint8Arrays
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Convert a string to Uint8Array (UTF-8 encoding)
 */
export function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Convert a Uint8Array to string (UTF-8 decoding)
 */
export function bytesToString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

/**
 * Convert a number to a Uint8Array (big-endian)
 */
export function numberToBytes(n: number, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  let value = n;
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = value & 0xff;
    value >>>= 8;
  }
  return bytes;
}

/**
 * Generate cryptographically secure random bytes
 */
export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Constant-time comparison of two Uint8Arrays
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

/**
 * Count the number of set bits (Hamming weight)
 */
export function popcount(n: number): number {
  let count = 0;
  while (n) {
    count += n & 1;
    n >>>= 1;
  }
  return count;
}

/**
 * Compute Hamming distance between two byte arrays
 */
export function hammingDistance(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) {
    throw new Error('Arrays must have equal length');
  }
  let distance = 0;
  for (let i = 0; i < a.length; i++) {
    distance += popcount(a[i] ^ b[i]);
  }
  return distance;
}

