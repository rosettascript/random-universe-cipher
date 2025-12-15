/**
 * Random Universe Cipher - Constants
 * 
 * Cryptographic constants and domain separators
 */

import type { RUCConfig } from './types';

/**
 * Default configuration for 256-bit quantum-resistant security
 */
export const CONFIG: RUCConfig = {
  keySize: 512,           // bits
  blockSize: 256,         // bits (32 bytes)
  rounds: 24,
  registerSize: 512,      // bits (64 bytes)
  registerCount: 7,
  accumulatorSize: 1024,  // bits (128 bytes)
  minSelectors: 16,
  maxSelectors: 31,
} as const;

/**
 * Byte sizes derived from bit sizes
 */
export const BYTES = {
  KEY: 64,           // 512 bits
  BLOCK: 32,         // 256 bits
  REGISTER: 64,      // 512 bits
  ACCUMULATOR: 128,  // 1024 bits
  IV: 32,            // 256 bits
  NONCE: 16,         // 128 bits for CTR mode
} as const;

/**
 * GF(2^8) irreducible polynomial: x^8 + x^4 + x^3 + x + 1
 * Reduced form (without x^8 term): 0x1B
 * Full form: 0x11B
 */
export const GF_POLYNOMIAL = 0x1b;
export const GF_POLYNOMIAL_FULL = 0x11b;

/**
 * Domain separation strings for SHAKE256
 * Ensures different derivations produce independent outputs
 */
export const DOMAIN = {
  REGISTER: 'RUC-REG',
  SELECTOR: 'RUC-SEL',
  PERMUTE: 'RUC-PERM',
  ROUND_KEY: 'RUC-RK',
  SBOX: 'RUC-SBOX',
  CONSTANT: 'RUC-CONST',
  IV_EXPAND: 'RUC-IV-EXPAND',
  PRIORITY: 'RUC-PRIO',
  KEYSTREAM: 'RUC-KS',
  CTR_IV: 'RUC-CTR-IV',
} as const;

/**
 * Bit masks for various sizes
 */
export const MASK = {
  U8: 0xffn,
  U16: 0xffffn,
  U32: 0xffffffffn,
  U64: 0xffffffffffffffffn,
  U512: (1n << 512n) - 1n,
  U1024: (1n << 1024n) - 1n,
} as const;

/**
 * ChaCha20 constants ("expand 32-byte k")
 */
export const CHACHA_CONSTANTS = new Uint32Array([
  0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
]);

