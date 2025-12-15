/**
 * Random Universe Cipher - Block Cipher Modes
 * 
 * Implementations of CTR and CBC modes for variable-length messages
 */

import { BYTES, DOMAIN } from './constants';
import { expandKey, mixIVIntoState } from './key-expansion';
import { encryptBlock, createCipherState } from './encrypt';
import { decryptBlock } from './decrypt';
import { shake256Hash } from './shake256';
import { concatBytes, stringToBytes, randomBytes, bytesToBigInt } from './bigint-utils';

/**
 * PKCS#7 padding
 */
function pkcs7Pad(data: Uint8Array, blockSize: number): Uint8Array {
  const paddingLen = blockSize - (data.length % blockSize);
  const padded = new Uint8Array(data.length + paddingLen);
  padded.set(data);
  for (let i = data.length; i < padded.length; i++) {
    padded[i] = paddingLen;
  }
  return padded;
}

/**
 * Remove PKCS#7 padding
 */
function pkcs7Unpad(data: Uint8Array): Uint8Array {
  if (data.length === 0) {
    throw new Error('Cannot unpad empty data');
  }
  
  const paddingLen = data[data.length - 1];
  
  if (paddingLen === 0 || paddingLen > data.length || paddingLen > BYTES.BLOCK) {
    throw new Error('Invalid padding');
  }
  
  // Verify all padding bytes
  for (let i = data.length - paddingLen; i < data.length; i++) {
    if (data[i] !== paddingLen) {
      throw new Error('Invalid padding');
    }
  }
  
  return data.subarray(0, data.length - paddingLen);
}

/**
 * CTR Mode Encryption
 * 
 * Each block can be encrypted independently (parallelizable)
 * Output format: nonce (16 bytes) || ciphertext
 */
export function encryptCTR(
  plaintext: Uint8Array,
  key: Uint8Array,
  nonce?: Uint8Array
): Uint8Array {
  // Generate nonce if not provided
  const actualNonce = nonce || randomBytes(BYTES.NONCE);
  if (actualNonce.length !== BYTES.NONCE) {
    throw new Error(`Nonce must be ${BYTES.NONCE} bytes`);
  }
  
  // Derive IV from nonce
  const iv = shake256Hash(
    concatBytes(actualNonce, stringToBytes(DOMAIN.CTR_IV)),
    BYTES.IV
  );
  
  // Key expansion
  const keyMaterial = expandKey(key);
  
  // Pad plaintext
  const padded = pkcs7Pad(plaintext, BYTES.BLOCK);
  const numBlocks = padded.length / BYTES.BLOCK;
  
  // Allocate output: nonce + ciphertext
  const output = new Uint8Array(BYTES.NONCE + padded.length);
  output.set(actualNonce, 0);
  
  // Encrypt each block
  // In CTR mode, each block uses independent state derived from counter
  for (let n = 0; n < numBlocks; n++) {
    // Create fresh state for this block
    const state = createCipherState(keyMaterial);
    
    // Mix IV into state
    mixIVIntoState(state.registers, iv);
    
    // Incorporate counter into state
    const counterBytes = new Uint8Array(8);
    const counterView = new DataView(counterBytes.buffer);
    counterView.setBigUint64(0, BigInt(n), false); // Big-endian
    
    const counterHash = shake256Hash(
      concatBytes(counterBytes, stringToBytes('CTR')),
      BYTES.REGISTER
    );
    const counterInt = bytesToBigInt(counterHash);
    state.registers[0] ^= counterInt;
    
    // Extract plaintext block
    const pBlock = padded.subarray(n * BYTES.BLOCK, (n + 1) * BYTES.BLOCK);
    
    // Encrypt
    const cBlock = encryptBlock(pBlock, key, iv, BigInt(n), state, keyMaterial);
    
    // Store ciphertext
    output.set(cBlock, BYTES.NONCE + n * BYTES.BLOCK);
  }
  
  return output;
}

/**
 * CTR Mode Decryption
 * 
 * Input format: nonce (16 bytes) || ciphertext
 */
export function decryptCTR(
  ciphertext: Uint8Array,
  key: Uint8Array
): Uint8Array {
  if (ciphertext.length < BYTES.NONCE + BYTES.BLOCK) {
    throw new Error('Ciphertext too short');
  }
  
  // Extract nonce
  const nonce = ciphertext.subarray(0, BYTES.NONCE);
  const encryptedData = ciphertext.subarray(BYTES.NONCE);
  
  if (encryptedData.length % BYTES.BLOCK !== 0) {
    throw new Error('Invalid ciphertext length');
  }
  
  // Derive IV from nonce
  const iv = shake256Hash(
    concatBytes(nonce, stringToBytes(DOMAIN.CTR_IV)),
    BYTES.IV
  );
  
  // Key expansion
  const keyMaterial = expandKey(key);
  
  const numBlocks = encryptedData.length / BYTES.BLOCK;
  const padded = new Uint8Array(encryptedData.length);
  
  // Decrypt each block
  for (let n = 0; n < numBlocks; n++) {
    // Create fresh state for this block
    const state = createCipherState(keyMaterial);
    
    // Mix IV into state
    mixIVIntoState(state.registers, iv);
    
    // Incorporate counter into state
    const counterBytes = new Uint8Array(8);
    const counterView = new DataView(counterBytes.buffer);
    counterView.setBigUint64(0, BigInt(n), false);
    
    const counterHash = shake256Hash(
      concatBytes(counterBytes, stringToBytes('CTR')),
      BYTES.REGISTER
    );
    const counterInt = bytesToBigInt(counterHash);
    state.registers[0] ^= counterInt;
    
    // Extract ciphertext block
    const cBlock = encryptedData.subarray(n * BYTES.BLOCK, (n + 1) * BYTES.BLOCK);
    
    // Decrypt
    const pBlock = decryptBlock(cBlock, key, iv, BigInt(n), state, keyMaterial);
    
    // Store plaintext
    padded.set(pBlock, n * BYTES.BLOCK);
  }
  
  // Remove padding
  return pkcs7Unpad(padded);
}

/**
 * CBC Mode Encryption
 * 
 * Sequential processing (each block depends on previous)
 * Output format: iv (32 bytes) || ciphertext
 */
export function encryptCBC(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv?: Uint8Array
): Uint8Array {
  // Generate IV if not provided
  const actualIV = iv || randomBytes(BYTES.IV);
  if (actualIV.length !== BYTES.IV) {
    throw new Error(`IV must be ${BYTES.IV} bytes`);
  }
  
  // Key expansion
  const keyMaterial = expandKey(key);
  
  // Create state and mix IV
  const state = createCipherState(keyMaterial);
  mixIVIntoState(state.registers, actualIV);
  
  // Pad plaintext
  const padded = pkcs7Pad(plaintext, BYTES.BLOCK);
  const numBlocks = padded.length / BYTES.BLOCK;
  
  // Allocate output: IV + ciphertext
  const output = new Uint8Array(BYTES.IV + padded.length);
  output.set(actualIV, 0);
  
  let prevCiphertext = actualIV;
  
  // Encrypt each block
  for (let n = 0; n < numBlocks; n++) {
    // Extract plaintext block
    const pBlock = padded.subarray(n * BYTES.BLOCK, (n + 1) * BYTES.BLOCK);
    
    // CBC: XOR with previous ciphertext
    const xoredBlock = new Uint8Array(BYTES.BLOCK);
    for (let i = 0; i < BYTES.BLOCK; i++) {
      xoredBlock[i] = pBlock[i] ^ prevCiphertext[i];
    }
    
    // Encrypt
    const cBlock = encryptBlock(xoredBlock, key, actualIV, BigInt(n), state, keyMaterial);
    
    // Store and update previous
    output.set(cBlock, BYTES.IV + n * BYTES.BLOCK);
    prevCiphertext = cBlock;
  }
  
  return output;
}

/**
 * CBC Mode Decryption
 * 
 * Input format: iv (32 bytes) || ciphertext
 */
export function decryptCBC(
  ciphertext: Uint8Array,
  key: Uint8Array
): Uint8Array {
  if (ciphertext.length < BYTES.IV + BYTES.BLOCK) {
    throw new Error('Ciphertext too short');
  }
  
  // Extract IV
  const iv = ciphertext.subarray(0, BYTES.IV);
  const encryptedData = ciphertext.subarray(BYTES.IV);
  
  if (encryptedData.length % BYTES.BLOCK !== 0) {
    throw new Error('Invalid ciphertext length');
  }
  
  // Key expansion
  const keyMaterial = expandKey(key);
  
  // Create state and mix IV
  const state = createCipherState(keyMaterial);
  mixIVIntoState(state.registers, iv);
  
  const numBlocks = encryptedData.length / BYTES.BLOCK;
  const padded = new Uint8Array(encryptedData.length);
  
  let prevCiphertext = iv;
  
  // Decrypt each block
  for (let n = 0; n < numBlocks; n++) {
    // Extract ciphertext block
    const cBlock = encryptedData.subarray(n * BYTES.BLOCK, (n + 1) * BYTES.BLOCK);
    
    // Decrypt
    const xoredBlock = decryptBlock(cBlock, key, iv, BigInt(n), state, keyMaterial);
    
    // CBC: XOR with previous ciphertext
    for (let i = 0; i < BYTES.BLOCK; i++) {
      padded[n * BYTES.BLOCK + i] = xoredBlock[i] ^ prevCiphertext[i];
    }
    
    prevCiphertext = cBlock;
  }
  
  // Remove padding
  return pkcs7Unpad(padded);
}

/**
 * Simple encryption with auto-generated nonce (convenience function)
 */
export function encrypt(plaintext: Uint8Array, key: Uint8Array): Uint8Array {
  return encryptCTR(plaintext, key);
}

/**
 * Simple decryption (convenience function)
 */
export function decrypt(ciphertext: Uint8Array, key: Uint8Array): Uint8Array {
  return decryptCTR(ciphertext, key);
}

