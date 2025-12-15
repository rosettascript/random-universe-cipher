/**
 * Encryption/Decryption Round-Trip Tests
 */

import { describe, it, expect } from 'vitest';
import {
  RandomUniverseCipher,
  encryptCTR,
  decryptCTR,
  encryptCBC,
  decryptCBC,
  expandKey,
  createCipherState,
  encryptBlock,
  decryptBlock,
  mixIVIntoState,
  generateRandomKey,
  generateRandomIV,
  generateRandomNonce,
  BYTES,
} from '../src/cipher';
import { randomBytes, stringToBytes, bytesToString } from '../src/cipher/bigint-utils';

describe('Block Encryption/Decryption', () => {
  it('should decrypt what it encrypts (single block)', () => {
    const key = generateRandomKey();
    const iv = generateRandomIV();
    const plaintext = randomBytes(BYTES.BLOCK);
    
    const keyMaterial = expandKey(key);
    
    // Encrypt
    const encState = createCipherState(keyMaterial);
    mixIVIntoState(encState.registers, iv);
    const ciphertext = encryptBlock(plaintext, key, iv, 0n, encState, keyMaterial);
    
    // Decrypt (fresh state)
    const decKeyMaterial = expandKey(key);
    const decState = createCipherState(decKeyMaterial);
    mixIVIntoState(decState.registers, iv);
    const decrypted = decryptBlock(ciphertext, key, iv, 0n, decState, decKeyMaterial);
    
    expect(decrypted).toEqual(plaintext);
  });

  it('should produce different ciphertext for different plaintexts', () => {
    const key = generateRandomKey();
    const iv = generateRandomIV();
    const keyMaterial = expandKey(key);
    
    const plaintext1 = randomBytes(BYTES.BLOCK);
    const plaintext2 = randomBytes(BYTES.BLOCK);
    
    const state1 = createCipherState(keyMaterial);
    mixIVIntoState(state1.registers, iv);
    const ciphertext1 = encryptBlock(plaintext1, key, iv, 0n, state1, keyMaterial);
    
    const state2 = createCipherState(keyMaterial);
    mixIVIntoState(state2.registers, iv);
    const ciphertext2 = encryptBlock(plaintext2, key, iv, 0n, state2, keyMaterial);
    
    expect(ciphertext1).not.toEqual(ciphertext2);
  });
});

describe('CTR Mode', () => {
  it('should round-trip short messages', () => {
    const key = generateRandomKey();
    const plaintext = stringToBytes('Hello, World!');
    
    const ciphertext = encryptCTR(plaintext, key);
    const decrypted = decryptCTR(ciphertext, key);
    
    expect(decrypted).toEqual(plaintext);
  });

  it('should round-trip exact block size', () => {
    const key = generateRandomKey();
    const plaintext = randomBytes(BYTES.BLOCK);
    
    const ciphertext = encryptCTR(plaintext, key);
    const decrypted = decryptCTR(ciphertext, key);
    
    expect(decrypted).toEqual(plaintext);
  });

  it('should round-trip multiple blocks', () => {
    const key = generateRandomKey();
    const plaintext = randomBytes(BYTES.BLOCK * 3 + 17); // 3.5+ blocks
    
    const ciphertext = encryptCTR(plaintext, key);
    const decrypted = decryptCTR(ciphertext, key);
    
    expect(decrypted).toEqual(plaintext);
  });

  it('should round-trip large messages', () => {
    const key = generateRandomKey();
    const plaintext = randomBytes(1024); // 1KB
    
    const ciphertext = encryptCTR(plaintext, key);
    const decrypted = decryptCTR(ciphertext, key);
    
    expect(decrypted).toEqual(plaintext);
  });

  it('should produce different ciphertext with different nonces', () => {
    const key = generateRandomKey();
    const plaintext = stringToBytes('Same message');
    
    const nonce1 = generateRandomNonce();
    const nonce2 = generateRandomNonce();
    
    const ciphertext1 = encryptCTR(plaintext, key, nonce1);
    const ciphertext2 = encryptCTR(plaintext, key, nonce2);
    
    expect(ciphertext1).not.toEqual(ciphertext2);
  });

  it('should fail to decrypt with wrong key', () => {
    const key1 = generateRandomKey();
    const key2 = generateRandomKey();
    const plaintext = stringToBytes('Secret message');
    
    const ciphertext = encryptCTR(plaintext, key1);
    
    // Decryption with wrong key will likely produce invalid padding
    // or garbage output - both are acceptable
    try {
      const decrypted = decryptCTR(ciphertext, key2);
      // If it doesn't throw, the result should be garbage
      expect(bytesToString(decrypted)).not.toBe('Secret message');
    } catch (e) {
      // Invalid padding error is expected with wrong key
      expect((e as Error).message).toContain('padding');
    }
  });
});

describe('CBC Mode', () => {
  it('should round-trip short messages', () => {
    const key = generateRandomKey();
    const plaintext = stringToBytes('Hello, CBC Mode!');
    
    const ciphertext = encryptCBC(plaintext, key);
    const decrypted = decryptCBC(ciphertext, key);
    
    expect(decrypted).toEqual(plaintext);
  });

  it('should round-trip multiple blocks', () => {
    const key = generateRandomKey();
    const plaintext = randomBytes(BYTES.BLOCK * 5 + 7);
    
    const ciphertext = encryptCBC(plaintext, key);
    const decrypted = decryptCBC(ciphertext, key);
    
    expect(decrypted).toEqual(plaintext);
  });
});

describe('RandomUniverseCipher Class', () => {
  it('should encrypt and decrypt with key bytes', () => {
    const key = generateRandomKey();
    const cipher = new RandomUniverseCipher(key);
    
    const plaintext = 'Test message for cipher class';
    const ciphertext = cipher.encrypt(plaintext);
    const decrypted = cipher.decryptToString(ciphertext);
    
    expect(decrypted).toBe(plaintext);
  });

  it('should encrypt and decrypt with password', () => {
    const password = 'my-secret-password-123';
    const cipher = RandomUniverseCipher.fromPassword(password);
    
    const plaintext = 'Secret data protected by password';
    const ciphertext = cipher.encrypt(plaintext);
    const decrypted = cipher.decryptToString(ciphertext);
    
    expect(decrypted).toBe(plaintext);
  });

  it('should produce consistent results with same password', () => {
    const password = 'consistent-password';
    const cipher1 = RandomUniverseCipher.fromPassword(password);
    const cipher2 = RandomUniverseCipher.fromPassword(password);
    
    const nonce = generateRandomNonce();
    const plaintext = 'Same input';
    
    const ciphertext1 = cipher1.encrypt(plaintext, nonce);
    const ciphertext2 = cipher2.encrypt(plaintext, nonce);
    
    expect(ciphertext1).toEqual(ciphertext2);
  });

  it('should handle binary data', () => {
    const cipher = RandomUniverseCipher.fromPassword('binary-test');
    
    const binaryData = new Uint8Array([0, 1, 127, 128, 255, 0, 0, 255]);
    const ciphertext = cipher.encrypt(binaryData);
    const decrypted = cipher.decrypt(ciphertext);
    
    expect(decrypted).toEqual(binaryData);
  });

  it('should handle empty input', () => {
    const cipher = RandomUniverseCipher.fromPassword('empty-test');
    
    const ciphertext = cipher.encrypt('');
    const decrypted = cipher.decryptToString(ciphertext);
    
    expect(decrypted).toBe('');
  });

  it('should handle unicode text', () => {
    const cipher = RandomUniverseCipher.fromPassword('unicode-test');
    
    const plaintext = '你好世界 🌍 Привет мир émojis: 🔐🚀✨';
    const ciphertext = cipher.encrypt(plaintext);
    const decrypted = cipher.decryptToString(ciphertext);
    
    expect(decrypted).toBe(plaintext);
  });
});

describe('Determinism', () => {
  it('should produce identical output for identical inputs', () => {
    const key = generateRandomKey();
    const nonce = generateRandomNonce();
    const plaintext = stringToBytes('Deterministic test');
    
    const ciphertext1 = encryptCTR(plaintext, key, nonce);
    const ciphertext2 = encryptCTR(plaintext, key, nonce);
    
    expect(ciphertext1).toEqual(ciphertext2);
  });

  it('should be deterministic across multiple calls', () => {
    const password = 'deterministic-password';
    const plaintext = 'Same message every time';
    const nonce = new Uint8Array(16).fill(42);
    
    const results: Uint8Array[] = [];
    for (let i = 0; i < 5; i++) {
      const cipher = RandomUniverseCipher.fromPassword(password);
      results.push(cipher.encrypt(plaintext, nonce));
    }
    
    // All should be identical
    for (let i = 1; i < results.length; i++) {
      expect(results[i]).toEqual(results[0]);
    }
  });
});

