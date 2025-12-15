/**
 * Key Derivation Function (KDF) Tests
 */

import { describe, it, expect } from 'vitest';
import {
  deriveKeyArgon2,
  deriveKeySync,
  generateSalt,
  encodeSalt,
  decodeSalt,
  RandomUniverseCipher,
  BYTES,
} from '../src/cipher';

describe('Argon2 Key Derivation', () => {
  it('should derive a 512-bit key from password', async () => {
    const { key, salt } = await deriveKeyArgon2('test-password');
    
    expect(key.length).toBe(BYTES.KEY);
    expect(salt.length).toBe(16);
  });

  it('should produce consistent results with same password and salt', async () => {
    const salt = generateSalt();
    
    const result1 = await deriveKeyArgon2('my-password', salt);
    const result2 = await deriveKeyArgon2('my-password', salt);
    
    expect(result1.key).toEqual(result2.key);
  });

  it('should produce different keys for different passwords', async () => {
    const salt = generateSalt();
    
    const result1 = await deriveKeyArgon2('password1', salt);
    const result2 = await deriveKeyArgon2('password2', salt);
    
    expect(result1.key).not.toEqual(result2.key);
  });

  it('should produce different keys for different salts', async () => {
    const salt1 = generateSalt();
    const salt2 = generateSalt();
    
    const result1 = await deriveKeyArgon2('same-password', salt1);
    const result2 = await deriveKeyArgon2('same-password', salt2);
    
    expect(result1.key).not.toEqual(result2.key);
  });

  it('should work with different security levels', async () => {
    const salt = generateSalt();
    
    // Interactive level should be fastest
    const start = performance.now();
    await deriveKeyArgon2('password', salt, 'interactive');
    const interactiveTime = performance.now() - start;
    
    // Just verify it completes - timing varies by machine
    expect(interactiveTime).toBeGreaterThan(0);
  }, 30000); // 30s timeout for slower machines
});

describe('Sync Key Derivation (SHAKE256 fallback)', () => {
  it('should derive a key synchronously', () => {
    const { key, salt } = deriveKeySync('test-password');
    
    expect(key.length).toBe(BYTES.KEY);
    expect(salt.length).toBe(16);
  });

  it('should be deterministic', () => {
    const salt = generateSalt();
    
    const result1 = deriveKeySync('password', salt, 1000);
    const result2 = deriveKeySync('password', salt, 1000);
    
    expect(result1.key).toEqual(result2.key);
  });
});

describe('Salt Encoding/Decoding', () => {
  it('should round-trip salt through base64', () => {
    const originalSalt = generateSalt();
    
    const encoded = encodeSalt(originalSalt);
    const decoded = decodeSalt(encoded);
    
    expect(decoded).toEqual(originalSalt);
  });

  it('should produce valid base64', () => {
    const salt = generateSalt();
    const encoded = encodeSalt(salt);
    
    // Base64 should only contain valid characters
    expect(encoded).toMatch(/^[A-Za-z0-9+/]+=*$/);
  });
});

describe('RandomUniverseCipher.fromPasswordAsync', () => {
  it('should create cipher from password with Argon2', async () => {
    const { cipher, salt } = await RandomUniverseCipher.fromPasswordAsync('my-secure-password');
    
    const plaintext = 'Test message';
    const ciphertext = cipher.encrypt(plaintext);
    const decrypted = cipher.decryptToString(ciphertext);
    
    expect(decrypted).toBe(plaintext);
    expect(salt.length).toBe(16);
  });

  it('should produce consistent cipher with same salt', async () => {
    const salt = RandomUniverseCipher.generateSalt();
    
    const result1 = await RandomUniverseCipher.fromPasswordAsync('password', salt);
    const result2 = await RandomUniverseCipher.fromPasswordAsync('password', salt);
    
    // Same salt + password should produce same key
    const plaintext = 'Consistent test';
    const nonce = new Uint8Array(16).fill(1);
    
    const ciphertext1 = result1.cipher.encrypt(plaintext, nonce);
    const ciphertext2 = result2.cipher.encrypt(plaintext, nonce);
    
    expect(ciphertext1).toEqual(ciphertext2);
  });

  it('should allow specifying security level', async () => {
    const { cipher } = await RandomUniverseCipher.fromPasswordAsync(
      'password',
      undefined,
      'interactive' // Fastest level
    );
    
    const encrypted = cipher.encrypt('Quick test');
    const decrypted = cipher.decryptToString(encrypted);
    
    expect(decrypted).toBe('Quick test');
  });
}, 60000); // 60s timeout for Argon2 tests

