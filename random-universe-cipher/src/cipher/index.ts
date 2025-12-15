/**
 * Random Universe Cipher - Public API
 * 
 * High-level interface for the Random Universe Cipher
 */

// Re-export types
export type {
  RUCConfig,
  Uint512,
  Uint1024,
  SBox,
  KeyMaterial,
  CipherState,
  EncryptionResult,
  DecryptionResult,
} from './types';

// Re-export constants
export { CONFIG, BYTES, DOMAIN, GF_POLYNOMIAL } from './constants';

// Re-export key functions
export {
  expandKey,
  mixIVIntoState,
  deriveKeyFromPassword,
  generateRandomKey,
  generateRandomIV,
  generateRandomNonce,
} from './key-expansion';

// Re-export S-box functions
export {
  generateSBox,
  verifySBoxProperties,
  computeNonlinearity,
  computeDifferentialUniformity,
  computeAlgebraicDegree,
} from './sbox';

// Re-export encryption/decryption
export { encryptBlock, createCipherState, cloneCipherState } from './encrypt';
export { decryptBlock } from './decrypt';
export { encryptCTR, decryptCTR, encryptCBC, decryptCBC, encrypt, decrypt } from './modes';

// Re-export AEAD (authenticated encryption)
export { aeadEncrypt, aeadDecrypt, aeadEncryptString, aeadDecryptString } from './aead';

// Re-export KDF (key derivation)
export {
  deriveKeyArgon2,
  deriveKeySync,
  generateSalt,
  verifyPassword,
  encodeSalt,
  decodeSalt,
  KDF_PARAMS,
  type KDFLevel,
} from './kdf';

// Re-export utilities
export {
  bytesToBigInt,
  bigIntToBytes,
  stringToBytes,
  bytesToString,
  randomBytes,
  hammingDistance,
  concatBytes,
} from './bigint-utils';
export { gfMul, gfMulRegister } from './gf-math';

import type { EncryptionResult, DecryptionResult } from './types';
import { BYTES } from './constants';
import { deriveKeyFromPassword, generateRandomKey as genKey } from './key-expansion';
import { encryptCTR, decryptCTR } from './modes';
import { aeadEncrypt, aeadDecrypt } from './aead';
import { deriveKeyArgon2, generateSalt, type KDFLevel } from './kdf';
import { stringToBytes, bytesToString, randomBytes } from './bigint-utils';

/**
 * High-level cipher class for easy encryption/decryption
 */
export class RandomUniverseCipher {
  private key: Uint8Array;
  
  /**
   * Create a new cipher instance
   * @param key - 64-byte key, or string password to derive key from
   */
  constructor(key: Uint8Array | string) {
    if (typeof key === 'string') {
      // Derive key from password
      this.key = deriveKeyFromPassword(key);
    } else {
      if (key.length !== BYTES.KEY) {
        throw new Error(`Key must be ${BYTES.KEY} bytes (${BYTES.KEY * 8} bits)`);
      }
      this.key = new Uint8Array(key);
    }
  }
  
  /**
   * Encrypt data
   * @param plaintext - Data to encrypt (string or bytes)
   * @param nonce - Optional 16-byte nonce (auto-generated if not provided)
   * @returns Encrypted data (nonce prepended)
   */
  encrypt(plaintext: string | Uint8Array, nonce?: Uint8Array): Uint8Array {
    const data = typeof plaintext === 'string' 
      ? stringToBytes(plaintext) 
      : plaintext;
    
    return encryptCTR(data, this.key, nonce);
  }
  
  /**
   * Encrypt and return with timing info
   */
  encryptWithTiming(plaintext: string | Uint8Array, nonce?: Uint8Array): EncryptionResult {
    const start = performance.now();
    const ciphertext = this.encrypt(plaintext, nonce);
    const timeMs = performance.now() - start;
    return { ciphertext, timeMs };
  }
  
  /**
   * Decrypt data
   * @param ciphertext - Data to decrypt (nonce should be prepended)
   * @returns Decrypted bytes
   */
  decrypt(ciphertext: Uint8Array): Uint8Array {
    return decryptCTR(ciphertext, this.key);
  }
  
  /**
   * Decrypt and return string
   */
  decryptToString(ciphertext: Uint8Array): string {
    const bytes = this.decrypt(ciphertext);
    return bytesToString(bytes);
  }
  
  /**
   * Decrypt and return with timing info
   */
  decryptWithTiming(ciphertext: Uint8Array): DecryptionResult {
    const start = performance.now();
    const plaintext = this.decrypt(ciphertext);
    const timeMs = performance.now() - start;
    return { plaintext, timeMs };
  }
  
  // ========== AEAD (Authenticated Encryption) ==========
  
  /**
   * Encrypt with authentication (AEAD)
   * Provides both confidentiality AND integrity protection
   * 
   * @param plaintext - Data to encrypt
   * @param associatedData - Optional data to authenticate but not encrypt
   * @returns nonce || ciphertext || authentication tag
   */
  encryptAuthenticated(
    plaintext: string | Uint8Array,
    associatedData?: Uint8Array | string
  ): Uint8Array {
    const data = typeof plaintext === 'string' 
      ? stringToBytes(plaintext) 
      : plaintext;
    const ad = associatedData
      ? (typeof associatedData === 'string' ? stringToBytes(associatedData) : associatedData)
      : undefined;
    return aeadEncrypt(data, this.key, ad);
  }
  
  /**
   * Decrypt with authentication verification (AEAD)
   * Throws if authentication fails (data was tampered)
   * 
   * @param ciphertext - Output from encryptAuthenticated
   * @param associatedData - Must match what was used during encryption
   * @returns Decrypted plaintext
   * @throws Error if authentication fails
   */
  decryptAuthenticated(
    ciphertext: Uint8Array,
    associatedData?: Uint8Array | string
  ): Uint8Array {
    const ad = associatedData
      ? (typeof associatedData === 'string' ? stringToBytes(associatedData) : associatedData)
      : undefined;
    return aeadDecrypt(ciphertext, this.key, ad);
  }
  
  /**
   * Decrypt authenticated data to string
   */
  decryptAuthenticatedToString(
    ciphertext: Uint8Array,
    associatedData?: Uint8Array | string
  ): string {
    return bytesToString(this.decryptAuthenticated(ciphertext, associatedData));
  }
  
  /**
   * Get the raw key (be careful with this!)
   */
  getKey(): Uint8Array {
    return new Uint8Array(this.key);
  }
  
  /**
   * Generate a new random key
   */
  static generateKey(): Uint8Array {
    return genKey();
  }
  
  /**
   * Generate a random nonce
   */
  static generateNonce(): Uint8Array {
    return randomBytes(BYTES.NONCE);
  }
  
  /**
   * Create a cipher from a password (sync, uses SHAKE256)
   * For better security, use fromPasswordAsync with Argon2
   */
  static fromPassword(password: string, salt?: Uint8Array): RandomUniverseCipher {
    const key = deriveKeyFromPassword(password, salt);
    return new RandomUniverseCipher(key);
  }
  
  /**
   * Create a cipher from a password using Argon2id (recommended)
   * This is more secure against brute-force attacks
   * 
   * @param password - User password
   * @param salt - Optional salt (generated if not provided)
   * @param level - Security level: 'interactive', 'moderate', or 'sensitive'
   * @returns Promise resolving to { cipher, salt }
   */
  static async fromPasswordAsync(
    password: string,
    salt?: Uint8Array,
    level: KDFLevel = 'moderate'
  ): Promise<{ cipher: RandomUniverseCipher; salt: Uint8Array }> {
    const result = await deriveKeyArgon2(password, salt, level);
    return {
      cipher: new RandomUniverseCipher(result.key),
      salt: result.salt,
    };
  }
  
  /**
   * Generate a new random salt for password derivation
   */
  static generateSalt(): Uint8Array {
    return generateSalt();
  }
}

/**
 * Convenience function: Encrypt a string with a password
 */
export function encryptString(plaintext: string, password: string): string {
  const cipher = RandomUniverseCipher.fromPassword(password);
  const encrypted = cipher.encrypt(plaintext);
  return bytesToBase64(encrypted);
}

/**
 * Convenience function: Decrypt a string with a password
 */
export function decryptString(ciphertext: string, password: string): string {
  const cipher = RandomUniverseCipher.fromPassword(password);
  const encrypted = base64ToBytes(ciphertext);
  return cipher.decryptToString(encrypted);
}

/**
 * Convert bytes to base64
 */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convert base64 to bytes
 */
export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Convert bytes to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert hex string to bytes
 */
export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

// ============================================================
// PASSWORD-BASED ENCRYPTION WITH AUTO-BUNDLED SALT
// ============================================================
// These functions automatically handle salt management:
// - Encryption: generates salt, bundles it with ciphertext
// - Decryption: extracts salt from ciphertext, derives key
// Format: salt (16 bytes) || encrypted_data
// ============================================================

const SALT_SIZE = 16;

/**
 * Encrypt with password using Argon2id (salt auto-bundled)
 * 
 * Output format: salt (16) || nonce (16) || ciphertext
 * 
 * @param plaintext - Data to encrypt
 * @param password - Password for key derivation
 * @param level - Argon2 security level
 * @returns Ciphertext with salt prepended
 */
export async function encryptWithPassword(
  plaintext: string | Uint8Array,
  password: string,
  level: KDFLevel = 'interactive'
): Promise<Uint8Array> {
  const { cipher, salt } = await RandomUniverseCipher.fromPasswordAsync(password, undefined, level);
  const data = typeof plaintext === 'string' ? stringToBytes(plaintext) : plaintext;
  const encrypted = cipher.encrypt(data);
  
  // Bundle: salt || encrypted
  const result = new Uint8Array(SALT_SIZE + encrypted.length);
  result.set(salt, 0);
  result.set(encrypted, SALT_SIZE);
  return result;
}

/**
 * Decrypt with password (extracts salt automatically)
 * 
 * @param ciphertext - Output from encryptWithPassword
 * @param password - Password used during encryption
 * @param level - Must match the level used during encryption
 * @returns Decrypted data
 */
export async function decryptWithPassword(
  ciphertext: Uint8Array,
  password: string,
  level: KDFLevel = 'interactive'
): Promise<Uint8Array> {
  if (ciphertext.length < SALT_SIZE + BYTES.NONCE + BYTES.BLOCK) {
    throw new Error('Ciphertext too short');
  }
  
  // Extract salt
  const salt = ciphertext.subarray(0, SALT_SIZE);
  const encrypted = ciphertext.subarray(SALT_SIZE);
  
  // Derive key with extracted salt
  const { cipher } = await RandomUniverseCipher.fromPasswordAsync(password, salt, level);
  return cipher.decrypt(encrypted);
}

/**
 * Decrypt with password to string
 */
export async function decryptWithPasswordToString(
  ciphertext: Uint8Array,
  password: string,
  level: KDFLevel = 'interactive'
): Promise<string> {
  const decrypted = await decryptWithPassword(ciphertext, password, level);
  return bytesToString(decrypted);
}

/**
 * Encrypt with password using AEAD (authenticated, salt auto-bundled)
 * 
 * Output format: salt (16) || nonce (16) || ciphertext || tag (32)
 * 
 * This is the RECOMMENDED function for most use cases:
 * - Argon2id protects against password brute-force
 * - AEAD provides integrity (detects tampering)
 * - Salt is auto-managed
 * 
 * @param plaintext - Data to encrypt
 * @param password - Password for key derivation
 * @param associatedData - Optional data to authenticate but not encrypt
 * @param level - Argon2 security level
 */
export async function encryptWithPasswordAEAD(
  plaintext: string | Uint8Array,
  password: string,
  associatedData?: Uint8Array | string,
  level: KDFLevel = 'interactive'
): Promise<Uint8Array> {
  const { cipher, salt } = await RandomUniverseCipher.fromPasswordAsync(password, undefined, level);
  const encrypted = cipher.encryptAuthenticated(plaintext, associatedData);
  
  // Bundle: salt || encrypted (which includes nonce + ciphertext + tag)
  const result = new Uint8Array(SALT_SIZE + encrypted.length);
  result.set(salt, 0);
  result.set(encrypted, SALT_SIZE);
  return result;
}

/**
 * Decrypt with password using AEAD (extracts salt, verifies authenticity)
 * 
 * @throws Error if authentication fails (data tampered or wrong password)
 */
export async function decryptWithPasswordAEAD(
  ciphertext: Uint8Array,
  password: string,
  associatedData?: Uint8Array | string,
  level: KDFLevel = 'interactive'
): Promise<Uint8Array> {
  if (ciphertext.length < SALT_SIZE + BYTES.NONCE + BYTES.BLOCK + 32) {
    throw new Error('Ciphertext too short');
  }
  
  // Extract salt
  const salt = ciphertext.subarray(0, SALT_SIZE);
  const encrypted = ciphertext.subarray(SALT_SIZE);
  
  // Derive key with extracted salt
  const { cipher } = await RandomUniverseCipher.fromPasswordAsync(password, salt, level);
  return cipher.decryptAuthenticated(encrypted, associatedData);
}

/**
 * Decrypt with password AEAD to string
 */
export async function decryptWithPasswordAEADToString(
  ciphertext: Uint8Array,
  password: string,
  associatedData?: Uint8Array | string,
  level: KDFLevel = 'interactive'
): Promise<string> {
  const decrypted = await decryptWithPasswordAEAD(ciphertext, password, associatedData, level);
  return bytesToString(decrypted);
}

/**
 * RECOMMENDED: Encrypt string with password (AEAD + Argon2, returns base64)
 * 
 * This is the simplest and most secure way to encrypt:
 * ```typescript
 * const encrypted = await secureEncrypt("secret message", "my-password");
 * const decrypted = await secureDecrypt(encrypted, "my-password");
 * ```
 */
export async function secureEncrypt(
  plaintext: string,
  password: string,
  level: KDFLevel = 'interactive'
): Promise<string> {
  const encrypted = await encryptWithPasswordAEAD(plaintext, password, undefined, level);
  return bytesToBase64(encrypted);
}

/**
 * RECOMMENDED: Decrypt string with password (AEAD + Argon2, from base64)
 */
export async function secureDecrypt(
  ciphertext: string,
  password: string,
  level: KDFLevel = 'interactive'
): Promise<string> {
  const encrypted = base64ToBytes(ciphertext);
  return decryptWithPasswordAEADToString(encrypted, password, undefined, level);
}

