/**
 * Random Universe Cipher - Authenticated Encryption (AEAD)
 * 
 * Provides encrypt-then-MAC authenticated encryption using:
 * - RUC-CTR for encryption
 * - HMAC-SHA256 for authentication
 * 
 * Format: nonce (16) || ciphertext || tag (32)
 */

import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { encryptCTR, decryptCTR } from './modes';
import { shake256Hash } from './shake256';
import { concatBytes, stringToBytes, constantTimeEqual } from './bigint-utils';
import { BYTES } from './constants';

/**
 * Size of the authentication tag (HMAC-SHA256 output)
 */
const TAG_SIZE = 32;

/**
 * Derive separate encryption and MAC keys from a master key
 * This ensures the same key isn't used for both operations
 */
function deriveKeys(masterKey: Uint8Array): { encKey: Uint8Array; macKey: Uint8Array } {
  // Use SHAKE256 with domain separation to derive two independent keys
  const encKey = shake256Hash(
    concatBytes(masterKey, stringToBytes('RUC-AEAD-ENC')),
    BYTES.KEY
  );
  const macKey = shake256Hash(
    concatBytes(masterKey, stringToBytes('RUC-AEAD-MAC')),
    32 // HMAC-SHA256 key size
  );
  return { encKey, macKey };
}

/**
 * Compute authentication tag over ciphertext and optional associated data
 * 
 * @param macKey - Key for HMAC
 * @param ciphertext - The encrypted data (includes nonce)
 * @param associatedData - Optional additional data to authenticate (but not encrypt)
 */
function computeTag(
  macKey: Uint8Array,
  ciphertext: Uint8Array,
  associatedData?: Uint8Array
): Uint8Array {
  // Format: AD_length (8 bytes) || AD || ciphertext
  const adLen = associatedData?.length ?? 0;
  const adLenBytes = new Uint8Array(8);
  const view = new DataView(adLenBytes.buffer);
  view.setBigUint64(0, BigInt(adLen), false);
  
  const dataToAuth = associatedData
    ? concatBytes(adLenBytes, associatedData, ciphertext)
    : concatBytes(adLenBytes, ciphertext);
  
  return hmac(sha256, macKey, dataToAuth);
}

/**
 * AEAD Encrypt - Encrypt and authenticate data
 * 
 * @param plaintext - Data to encrypt
 * @param key - Master key (512 bits / 64 bytes)
 * @param associatedData - Optional data to authenticate but not encrypt
 * @param nonce - Optional 16-byte nonce (auto-generated if not provided)
 * @returns nonce || ciphertext || tag
 */
export function aeadEncrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  associatedData?: Uint8Array,
  nonce?: Uint8Array
): Uint8Array {
  // Derive separate keys for encryption and MAC
  const { encKey, macKey } = deriveKeys(key);
  
  // Encrypt with CTR mode (returns nonce || ciphertext)
  const ciphertext = encryptCTR(plaintext, encKey, nonce);
  
  // Compute authentication tag
  const tag = computeTag(macKey, ciphertext, associatedData);
  
  // Return ciphertext with tag appended
  return concatBytes(ciphertext, tag);
}

/**
 * AEAD Decrypt - Decrypt and verify authenticated data
 * 
 * @param ciphertextWithTag - nonce || ciphertext || tag
 * @param key - Master key (512 bits / 64 bytes)
 * @param associatedData - Optional associated data (must match what was used during encryption)
 * @returns Decrypted plaintext
 * @throws Error if authentication fails
 */
export function aeadDecrypt(
  ciphertextWithTag: Uint8Array,
  key: Uint8Array,
  associatedData?: Uint8Array
): Uint8Array {
  // Minimum size: nonce (16) + one block (32) + tag (32) = 80 bytes
  if (ciphertextWithTag.length < BYTES.NONCE + BYTES.BLOCK + TAG_SIZE) {
    throw new Error('Ciphertext too short');
  }
  
  // Split ciphertext and tag
  const ciphertext = ciphertextWithTag.subarray(0, ciphertextWithTag.length - TAG_SIZE);
  const providedTag = ciphertextWithTag.subarray(ciphertextWithTag.length - TAG_SIZE);
  
  // Derive keys
  const { encKey, macKey } = deriveKeys(key);
  
  // Compute expected tag
  const expectedTag = computeTag(macKey, ciphertext, associatedData);
  
  // Constant-time comparison to prevent timing attacks
  if (!constantTimeEqual(providedTag, expectedTag)) {
    throw new Error('Authentication failed: invalid tag');
  }
  
  // Tag verified - now decrypt
  return decryptCTR(ciphertext, encKey);
}

/**
 * AEAD Encrypt with string plaintext
 */
export function aeadEncryptString(
  plaintext: string,
  key: Uint8Array,
  associatedData?: Uint8Array | string
): Uint8Array {
  const plaintextBytes = stringToBytes(plaintext);
  const adBytes = associatedData 
    ? (typeof associatedData === 'string' ? stringToBytes(associatedData) : associatedData)
    : undefined;
  return aeadEncrypt(plaintextBytes, key, adBytes);
}

/**
 * AEAD Decrypt to string
 */
export function aeadDecryptString(
  ciphertextWithTag: Uint8Array,
  key: Uint8Array,
  associatedData?: Uint8Array | string
): string {
  const adBytes = associatedData 
    ? (typeof associatedData === 'string' ? stringToBytes(associatedData) : associatedData)
    : undefined;
  const plaintext = aeadDecrypt(ciphertextWithTag, key, adBytes);
  return new TextDecoder().decode(plaintext);
}

