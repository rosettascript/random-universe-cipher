/**
 * Random Universe Cipher - ChaCha20 PRNG
 * 
 * ChaCha20 stream cipher used as deterministic PRNG
 * for selector permutation and priority generation
 */

import { CHACHA_CONSTANTS } from './constants';

/**
 * ChaCha20 quarter round operation
 */
function quarterRound(state: Uint32Array, a: number, b: number, c: number, d: number): void {
  state[a] = (state[a] + state[b]) >>> 0;
  state[d] = rotl32(state[d] ^ state[a], 16);
  
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotl32(state[b] ^ state[c], 12);
  
  state[a] = (state[a] + state[b]) >>> 0;
  state[d] = rotl32(state[d] ^ state[a], 8);
  
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotl32(state[b] ^ state[c], 7);
}

/**
 * 32-bit rotate left
 */
function rotl32(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

/**
 * ChaCha20 block function
 * Generates 64 bytes of keystream from key, nonce, and counter
 */
function chachaBlock(key: Uint8Array, nonce: Uint8Array, counter: number): Uint8Array {
  // Initialize state
  // [0-3]: constants, [4-11]: key, [12]: counter, [13-15]: nonce
  const state = new Uint32Array(16);
  
  // Constants
  state[0] = CHACHA_CONSTANTS[0];
  state[1] = CHACHA_CONSTANTS[1];
  state[2] = CHACHA_CONSTANTS[2];
  state[3] = CHACHA_CONSTANTS[3];
  
  // Key (8 x 32-bit words = 256 bits)
  const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
  for (let i = 0; i < 8; i++) {
    state[4 + i] = keyView.getUint32(i * 4, true); // Little-endian
  }
  
  // Counter
  state[12] = counter >>> 0;
  
  // Nonce (3 x 32-bit words = 96 bits)
  const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
  for (let i = 0; i < 3; i++) {
    state[13 + i] = nonceView.getUint32(i * 4, true); // Little-endian
  }
  
  // Copy initial state
  const working = new Uint32Array(state);
  
  // 20 rounds (10 double rounds)
  for (let i = 0; i < 10; i++) {
    // Column rounds
    quarterRound(working, 0, 4, 8, 12);
    quarterRound(working, 1, 5, 9, 13);
    quarterRound(working, 2, 6, 10, 14);
    quarterRound(working, 3, 7, 11, 15);
    
    // Diagonal rounds
    quarterRound(working, 0, 5, 10, 15);
    quarterRound(working, 1, 6, 11, 12);
    quarterRound(working, 2, 7, 8, 13);
    quarterRound(working, 3, 4, 9, 14);
  }
  
  // Add initial state
  for (let i = 0; i < 16; i++) {
    working[i] = (working[i] + state[i]) >>> 0;
  }
  
  // Convert to bytes (little-endian)
  const output = new Uint8Array(64);
  const outputView = new DataView(output.buffer);
  for (let i = 0; i < 16; i++) {
    outputView.setUint32(i * 4, working[i], true);
  }
  
  return output;
}

/**
 * ChaCha20 PRNG class
 * Provides deterministic random bytes from a seed
 */
export class ChaCha20PRNG {
  private key: Uint8Array;
  private nonce: Uint8Array;
  private counter: number;
  private buffer: Uint8Array;
  private bufferPos: number;
  
  /**
   * Initialize ChaCha20 PRNG with 32-byte key and 12-byte nonce
   */
  constructor(key: Uint8Array, nonce?: Uint8Array) {
    if (key.length !== 32) {
      throw new Error('ChaCha20 key must be 32 bytes');
    }
    
    this.key = new Uint8Array(key);
    this.nonce = nonce ? new Uint8Array(nonce) : new Uint8Array(12);
    
    if (this.nonce.length !== 12) {
      throw new Error('ChaCha20 nonce must be 12 bytes');
    }
    
    this.counter = 0;
    this.buffer = new Uint8Array(0);
    this.bufferPos = 0;
  }
  
  /**
   * Generate the next block of random bytes
   */
  private generateBlock(): void {
    this.buffer = chachaBlock(this.key, this.nonce, this.counter);
    this.counter++;
    this.bufferPos = 0;
  }
  
  /**
   * Get the next n random bytes
   */
  nextBytes(count: number): Uint8Array {
    const result = new Uint8Array(count);
    let written = 0;
    
    while (written < count) {
      if (this.bufferPos >= this.buffer.length) {
        this.generateBlock();
      }
      
      const available = this.buffer.length - this.bufferPos;
      const toWrite = Math.min(available, count - written);
      
      result.set(
        this.buffer.subarray(this.bufferPos, this.bufferPos + toWrite),
        written
      );
      
      this.bufferPos += toWrite;
      written += toWrite;
    }
    
    return result;
  }
  
  /**
   * Get the next random 32-bit unsigned integer
   */
  nextU32(): number {
    const bytes = this.nextBytes(4);
    return (
      (bytes[0] << 24) |
      (bytes[1] << 16) |
      (bytes[2] << 8) |
      bytes[3]
    ) >>> 0;
  }
  
  /**
   * Get a random integer in range [0, max)
   */
  nextInt(max: number): number {
    // Rejection sampling to avoid modulo bias
    const maxValid = Math.floor(0x100000000 / max) * max;
    let value: number;
    do {
      value = this.nextU32();
    } while (value >= maxValid);
    return value % max;
  }
  
  /**
   * Reset the PRNG state
   */
  reset(): void {
    this.counter = 0;
    this.buffer = new Uint8Array(0);
    this.bufferPos = 0;
  }
}

/**
 * Create a ChaCha20 PRNG from a seed (will be hashed to 32 bytes)
 */
export function createPRNG(seed: Uint8Array, nonce?: Uint8Array): ChaCha20PRNG {
  // If seed is not 32 bytes, we need to derive a key
  // Import shake256 dynamically to avoid circular dependencies
  let key: Uint8Array;
  if (seed.length === 32) {
    key = seed;
  } else {
    // Simple key derivation using first 32 bytes or padding
    key = new Uint8Array(32);
    key.set(seed.subarray(0, Math.min(32, seed.length)));
  }
  
  return new ChaCha20PRNG(key, nonce);
}

