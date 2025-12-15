/**
 * Random Universe Cipher - Type Definitions
 * 
 * Core types for the 256-bit quantum-resistant security level
 */

/**
 * Cipher configuration constants
 */
export interface RUCConfig {
  readonly keySize: 512;           // bits
  readonly blockSize: 256;         // bits
  readonly rounds: 24;
  readonly registerSize: 512;      // bits
  readonly registerCount: 7;
  readonly accumulatorSize: 1024;  // bits
  readonly minSelectors: 16;
  readonly maxSelectors: 31;
}

/**
 * 512-bit unsigned integer represented as native BigInt
 */
export type Uint512 = bigint;

/**
 * 1024-bit unsigned integer for accumulator
 */
export type Uint1024 = bigint;

/**
 * S-Box: 256-byte substitution box (bijective permutation)
 */
export type SBox = Uint8Array;

/**
 * Key material derived from the master key
 */
export interface KeyMaterial {
  /** 7 state registers, each 512 bits */
  registers: Uint512[];
  /** 16-31 odd selector values (16-bit each) */
  selectors: number[];
  /** 24 round keys, each 512 bits */
  roundKeys: Uint512[];
  /** 24 S-boxes, each 256 bytes */
  sboxes: SBox[];
}

/**
 * Cipher state during encryption/decryption
 */
export interface CipherState {
  /** 7 state registers */
  registers: Uint512[];
  /** 1024-bit accumulator */
  accumulator: Uint1024;
}

/**
 * Encryption result with metadata
 */
export interface EncryptionResult {
  /** Encrypted ciphertext (includes nonce) */
  ciphertext: Uint8Array;
  /** Encryption time in milliseconds */
  timeMs: number;
}

/**
 * Decryption result with metadata
 */
export interface DecryptionResult {
  /** Decrypted plaintext */
  plaintext: Uint8Array;
  /** Decryption time in milliseconds */
  timeMs: number;
}

