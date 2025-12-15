/**
 * Random Universe Cipher - Key Derivation Functions
 * 
 * Secure password-based key derivation using Argon2id (via hash-wasm)
 * with fallback to SHAKE256 for environments without WASM support
 */

import { argon2id } from 'hash-wasm';
import { shake256Hash } from './shake256';
import { concatBytes, stringToBytes, randomBytes } from './bigint-utils';
import { BYTES } from './constants';

/**
 * Argon2id parameters for different security levels
 */
export const KDF_PARAMS = {
  /** Interactive: Fast, suitable for login (t=2, m=64MB) */
  interactive: {
    iterations: 2,
    memorySize: 65536, // 64 MB in KB
    parallelism: 1,
  },
  /** Moderate: Balanced security/performance (t=3, m=64MB) */
  moderate: {
    iterations: 3,
    memorySize: 65536, // 64 MB in KB
    parallelism: 1,
  },
  /** Sensitive: High security, slower (t=4, m=128MB) */
  sensitive: {
    iterations: 4,
    memorySize: 131072, // 128 MB in KB
    parallelism: 1,
  },
} as const;

export type KDFLevel = keyof typeof KDF_PARAMS;

/**
 * Salt size for key derivation (128 bits)
 */
const SALT_SIZE = 16;

/**
 * Derive a key from a password using Argon2id
 * 
 * @param password - User password
 * @param salt - 16-byte salt (generated if not provided)
 * @param level - Security level (interactive, moderate, sensitive)
 * @returns Object containing the derived key and salt
 */
export async function deriveKeyArgon2(
  password: string,
  salt?: Uint8Array,
  level: KDFLevel = 'moderate'
): Promise<{ key: Uint8Array; salt: Uint8Array }> {
  const actualSalt = salt || randomBytes(SALT_SIZE);
  
  if (actualSalt.length !== SALT_SIZE) {
    throw new Error(`Salt must be ${SALT_SIZE} bytes`);
  }
  
  const params = KDF_PARAMS[level];
  
  try {
    const hash = await argon2id({
      password,
      salt: actualSalt,
      iterations: params.iterations,
      memorySize: params.memorySize,
      parallelism: params.parallelism,
      hashLength: BYTES.KEY, // 64 bytes = 512 bits
      outputType: 'binary',
    });
    
    return {
      key: hash,
      salt: actualSalt,
    };
  } catch (error) {
    // Fallback to SHAKE256 if Argon2 fails (e.g., WASM not supported)
    console.warn('Argon2 failed, falling back to SHAKE256:', error);
    return deriveKeyShake256(password, actualSalt, params.iterations);
  }
}

/**
 * Fallback key derivation using iterated SHAKE256
 * Less secure than Argon2 but works everywhere
 */
function deriveKeyShake256(
  password: string,
  salt: Uint8Array,
  iterations: number
): { key: Uint8Array; salt: Uint8Array } {
  const passwordBytes = stringToBytes(password);
  let derived = shake256Hash(concatBytes(passwordBytes, salt), BYTES.KEY);
  
  // Apply iterations (simple key stretching)
  for (let i = 0; i < iterations * 10000; i++) {
    derived = shake256Hash(concatBytes(derived, salt, passwordBytes), BYTES.KEY);
  }
  
  return { key: derived, salt };
}

/**
 * Synchronous key derivation using SHAKE256 (for compatibility)
 * Use deriveKeyArgon2 when async is acceptable
 */
export function deriveKeySync(
  password: string,
  salt?: Uint8Array,
  iterations: number = 100000
): { key: Uint8Array; salt: Uint8Array } {
  const actualSalt = salt || randomBytes(SALT_SIZE);
  return deriveKeyShake256(password, actualSalt, Math.ceil(iterations / 10000));
}

/**
 * Generate a random salt for key derivation
 */
export function generateSalt(): Uint8Array {
  return randomBytes(SALT_SIZE);
}

/**
 * Verify a password against a known salt and expected key
 * Useful for password verification without storing the key
 */
export async function verifyPassword(
  password: string,
  salt: Uint8Array,
  expectedKey: Uint8Array,
  level: KDFLevel = 'moderate'
): Promise<boolean> {
  const { key } = await deriveKeyArgon2(password, salt, level);
  
  // Constant-time comparison
  if (key.length !== expectedKey.length) return false;
  let result = 0;
  for (let i = 0; i < key.length; i++) {
    result |= key[i] ^ expectedKey[i];
  }
  return result === 0;
}

/**
 * Encode salt for storage/transmission (base64)
 */
export function encodeSalt(salt: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < salt.length; i++) {
    binary += String.fromCharCode(salt[i]);
  }
  return btoa(binary);
}

/**
 * Decode salt from storage/transmission (base64)
 */
export function decodeSalt(encoded: string): Uint8Array {
  const binary = atob(encoded);
  const salt = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    salt[i] = binary.charCodeAt(i);
  }
  return salt;
}
