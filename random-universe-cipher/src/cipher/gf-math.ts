/**
 * Random Universe Cipher - Galois Field Mathematics
 * 
 * GF(2^8) operations with polynomial x^8 + x^4 + x^3 + x + 1
 */

import { GF_POLYNOMIAL } from './constants';
import { BYTES } from './constants';

/**
 * Precomputed multiplication table for GF(2^8)
 * gfMulTable[a][b] = a * b in GF(2^8)
 */
let gfMulTable: Uint8Array[] | null = null;

/**
 * Initialize the GF(2^8) multiplication lookup table
 * This provides O(1) multiplication at the cost of 64KB memory
 */
function initGfMulTable(): Uint8Array[] {
  if (gfMulTable) return gfMulTable;
  
  gfMulTable = new Array(256);
  for (let a = 0; a < 256; a++) {
    gfMulTable[a] = new Uint8Array(256);
    for (let b = 0; b < 256; b++) {
      gfMulTable[a][b] = gfMulSlow(a, b);
    }
  }
  return gfMulTable;
}

/**
 * Multiply two elements in GF(2^8) without lookup table
 * Used to build the lookup table and as fallback
 */
function gfMulSlow(a: number, b: number): number {
  let result = 0;
  let aa = a;
  let bb = b;
  
  for (let i = 0; i < 8; i++) {
    if (bb & 1) {
      result ^= aa;
    }
    
    const highBit = aa & 0x80;
    aa = (aa << 1) & 0xff;
    
    if (highBit) {
      aa ^= GF_POLYNOMIAL;
    }
    
    bb >>>= 1;
  }
  
  return result;
}

/**
 * Multiply two elements in GF(2^8) using lookup table
 */
export function gfMul(a: number, b: number): number {
  const table = initGfMulTable();
  return table[a & 0xff][b & 0xff];
}

/**
 * Multiply each byte of a 512-bit register by a constant in GF(2^8)
 * This is the byte-wise GF multiplication specified in the cipher
 */
export function gfMulRegister(reg: bigint, multiplier: number): bigint {
  const table = initGfMulTable();
  const mult = multiplier & 0xff;
  let result = 0n;
  
  // Process each of the 64 bytes (512 bits / 8)
  for (let i = 0; i < BYTES.REGISTER; i++) {
    // Extract byte i (big-endian: byte 0 is most significant)
    const shift = BigInt((BYTES.REGISTER - 1 - i) * 8);
    const byteVal = Number((reg >> shift) & 0xffn);
    
    // GF multiply
    const product = table[byteVal][mult];
    
    // Place result
    result |= BigInt(product) << shift;
  }
  
  return result;
}

/**
 * Compute the multiplicative inverse in GF(2^8)
 * Returns 0 for input 0 (by convention)
 */
export function gfInverse(a: number): number {
  if (a === 0) return 0;
  
  // Use extended Euclidean algorithm or lookup
  // For simplicity, we use the property that a^254 = a^(-1) in GF(2^8)
  let result = a;
  for (let i = 0; i < 6; i++) {
    result = gfMul(result, result); // Square
    result = gfMul(result, a);      // Multiply by a
  }
  result = gfMul(result, result);   // Final square gives a^254
  return result;
}

/**
 * Compute a^n in GF(2^8) using square-and-multiply
 */
export function gfPow(a: number, n: number): number {
  if (n === 0) return 1;
  
  let result = 1;
  let base = a;
  
  while (n > 0) {
    if (n & 1) {
      result = gfMul(result, base);
    }
    base = gfMul(base, base);
    n >>>= 1;
  }
  
  return result;
}

/**
 * Add two elements in GF(2^8) - this is just XOR
 */
export function gfAdd(a: number, b: number): number {
  return a ^ b;
}

/**
 * Get the precomputed GF multiplication table
 * Useful for external verification
 */
export function getGfMulTable(): Uint8Array[] {
  return initGfMulTable();
}

