/**
 * Random Universe Cipher - Key Expansion
 * 
 * Derives all cipher materials from the master key:
 * - 7 state registers (512 bits each)
 * - 16-31 selectors (16-bit odd numbers)
 * - 24 round keys (512 bits each)
 * - 24 S-boxes (256 bytes each)
 */

import type { KeyMaterial, Uint512, SBox } from './types';
import { CONFIG, DOMAIN, BYTES } from './constants';
import { shake256Hash, shake256WithDomain } from './shake256';
import { ChaCha20PRNG } from './chacha20';
import { generateSBox } from './sbox';
import { bytesToBigInt, concatBytes, stringToBytes, rotateLeft512, xor512 } from './bigint-utils';

/**
 * Expand a master key into all cipher materials
 */
export function expandKey(key: Uint8Array): KeyMaterial {
  if (key.length !== BYTES.KEY) {
    throw new Error(`Key must be ${BYTES.KEY} bytes (${CONFIG.keySize} bits)`);
  }
  
  // Step 1: Generate 7 state registers
  const registers: Uint512[] = [];
  for (let i = 0; i < CONFIG.registerCount; i++) {
    const regBytes = shake256WithDomain(key, DOMAIN.REGISTER, i, BYTES.REGISTER);
    registers.push(bytesToBigInt(regBytes));
  }
  
  // Step 2: Determine selector count: 16 + (key[1] % 16)
  const numSelectors = CONFIG.minSelectors + (key[1] % (CONFIG.maxSelectors - CONFIG.minSelectors + 1));
  
  // Step 3: Generate selectors (must be odd)
  const selectors: number[] = [];
  for (let i = 0; i < numSelectors; i++) {
    const selBytes = shake256WithDomain(key, DOMAIN.SELECTOR, i, 2);
    let selector = (selBytes[0] << 8) | selBytes[1];
    
    // Ensure odd
    if (selector % 2 === 0) {
      selector += 1;
    }
    // Ensure non-zero
    if (selector === 0) {
      selector = 1;
    }
    
    selectors.push(selector);
  }
  
  // Step 4: Permute selectors using Fisher-Yates with ChaCha20 PRNG
  const permuteSeed = shake256Hash(
    concatBytes(key, stringToBytes(DOMAIN.PERMUTE)),
    32
  );
  const prng = new ChaCha20PRNG(permuteSeed);
  
  for (let i = numSelectors - 1; i > 0; i--) {
    const j = prng.nextInt(i + 1);
    // Swap
    const temp = selectors[i];
    selectors[i] = selectors[j];
    selectors[j] = temp;
  }
  
  // Step 5: Generate 24 round keys
  const roundKeys: Uint512[] = [];
  for (let r = 0; r < CONFIG.rounds; r++) {
    const rkBytes = shake256WithDomain(key, DOMAIN.ROUND_KEY, r, BYTES.REGISTER);
    roundKeys.push(bytesToBigInt(rkBytes));
  }
  
  // Step 6: Generate 24 S-boxes
  const sboxes: SBox[] = [];
  for (let r = 0; r < CONFIG.rounds; r++) {
    sboxes.push(generateSBox(key, r));
  }
  
  return {
    registers,
    selectors,
    roundKeys,
    sboxes,
  };
}

/**
 * Mix an IV into the state registers
 * This ensures different IVs produce different ciphertexts even with same key
 */
export function mixIVIntoState(registers: Uint512[], iv: Uint8Array): void {
  if (iv.length !== BYTES.IV) {
    throw new Error(`IV must be ${BYTES.IV} bytes`);
  }
  
  // Step 1: Expand IV to 512 bits using SHAKE256
  const ivExpanded = shake256Hash(
    concatBytes(iv, stringToBytes(DOMAIN.IV_EXPAND)),
    BYTES.REGISTER
  );
  const ivInt = bytesToBigInt(ivExpanded);
  
  // Step 2: Mix IV into each register with different rotations
  for (let i = 0; i < CONFIG.registerCount; i++) {
    const rotation = (i * 73) % 512; // Prime multiplier for good distribution
    const rotatedIV = rotateLeft512(ivInt, rotation);
    registers[i] = xor512(registers[i], rotatedIV);
  }
  
  // Step 3: Cross-mix registers to diffuse IV influence
  for (let round = 0; round < 3; round++) {
    for (let i = 0; i < CONFIG.registerCount; i++) {
      registers[i] = xor512(
        registers[i],
        rotateLeft512(registers[(i + 1) % CONFIG.registerCount], 17)
      );
      registers[i] = xor512(
        registers[i],
        rotateLeft512(registers[(i + 3) % CONFIG.registerCount], 41)
      );
    }
  }
}

/**
 * Clone key material (for independent state during encryption)
 */
export function cloneKeyMaterial(km: KeyMaterial): KeyMaterial {
  return {
    registers: km.registers.map(r => r),
    selectors: [...km.selectors],
    roundKeys: km.roundKeys.map(rk => rk),
    sboxes: km.sboxes.map(sb => new Uint8Array(sb)),
  };
}

/**
 * Clone registers array
 */
export function cloneRegisters(registers: Uint512[]): Uint512[] {
  return registers.map(r => r);
}

/**
 * Derive a proper cipher key from a password
 * For demo purposes, uses SHAKE256. Production should use Argon2.
 */
export function deriveKeyFromPassword(password: string, salt?: Uint8Array): Uint8Array {
  const passwordBytes = new TextEncoder().encode(password);
  const actualSalt = salt || new Uint8Array(16); // Default salt for demo
  
  // Simple key derivation - production should use Argon2id
  return shake256Hash(concatBytes(passwordBytes, actualSalt), BYTES.KEY);
}

/**
 * Generate a random key
 */
export function generateRandomKey(): Uint8Array {
  const key = new Uint8Array(BYTES.KEY);
  crypto.getRandomValues(key);
  return key;
}

/**
 * Generate a random IV
 */
export function generateRandomIV(): Uint8Array {
  const iv = new Uint8Array(BYTES.IV);
  crypto.getRandomValues(iv);
  return iv;
}

/**
 * Generate a random nonce for CTR mode
 */
export function generateRandomNonce(): Uint8Array {
  const nonce = new Uint8Array(BYTES.NONCE);
  crypto.getRandomValues(nonce);
  return nonce;
}

