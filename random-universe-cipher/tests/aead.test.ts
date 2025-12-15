/**
 * AEAD (Authenticated Encryption) Tests
 */

import { describe, it, expect } from 'vitest';
import {
  aeadEncrypt,
  aeadDecrypt,
  aeadEncryptString,
  aeadDecryptString,
  RandomUniverseCipher,
  generateRandomKey,
  BYTES,
} from '../src/cipher';
import { stringToBytes } from '../src/cipher/bigint-utils';

describe('AEAD Encryption', () => {
  it('should encrypt and decrypt successfully', () => {
    const key = generateRandomKey();
    const plaintext = stringToBytes('Hello, authenticated world!');
    
    const ciphertext = aeadEncrypt(plaintext, key);
    const decrypted = aeadDecrypt(ciphertext, key);
    
    expect(decrypted).toEqual(plaintext);
  });

  it('should work with string helpers', () => {
    const key = generateRandomKey();
    const plaintext = 'Secret message with AEAD';
    
    const ciphertext = aeadEncryptString(plaintext, key);
    const decrypted = aeadDecryptString(ciphertext, key);
    
    expect(decrypted).toBe(plaintext);
  });

  it('should include authentication tag in output', () => {
    const key = generateRandomKey();
    const plaintext = stringToBytes('Test');
    
    const ciphertext = aeadEncrypt(plaintext, key);
    
    // Output should be longer than regular CTR mode by 32 bytes (tag)
    // nonce (16) + padded_ciphertext (32) + tag (32) = 80 bytes minimum
    expect(ciphertext.length).toBeGreaterThanOrEqual(BYTES.NONCE + BYTES.BLOCK + 32);
  });

  it('should fail decryption if ciphertext is tampered', () => {
    const key = generateRandomKey();
    const plaintext = stringToBytes('Do not tamper!');
    
    const ciphertext = aeadEncrypt(plaintext, key);
    
    // Tamper with the ciphertext (not the tag)
    const tampered = new Uint8Array(ciphertext);
    tampered[BYTES.NONCE + 5] ^= 0xff; // Flip bits in encrypted data
    
    expect(() => aeadDecrypt(tampered, key)).toThrow('Authentication failed');
  });

  it('should fail decryption if tag is tampered', () => {
    const key = generateRandomKey();
    const plaintext = stringToBytes('Protect the tag!');
    
    const ciphertext = aeadEncrypt(plaintext, key);
    
    // Tamper with the tag (last 32 bytes)
    const tampered = new Uint8Array(ciphertext);
    tampered[tampered.length - 1] ^= 0x01;
    
    expect(() => aeadDecrypt(tampered, key)).toThrow('Authentication failed');
  });

  it('should fail decryption with wrong key', () => {
    const key1 = generateRandomKey();
    const key2 = generateRandomKey();
    const plaintext = stringToBytes('Wrong key test');
    
    const ciphertext = aeadEncrypt(plaintext, key1);
    
    expect(() => aeadDecrypt(ciphertext, key2)).toThrow('Authentication failed');
  });
});

describe('Associated Data', () => {
  it('should authenticate associated data', () => {
    const key = generateRandomKey();
    const plaintext = stringToBytes('Secret');
    const associatedData = stringToBytes('Header: public info');
    
    const ciphertext = aeadEncrypt(plaintext, key, associatedData);
    const decrypted = aeadDecrypt(ciphertext, key, associatedData);
    
    expect(decrypted).toEqual(plaintext);
  });

  it('should fail if associated data differs', () => {
    const key = generateRandomKey();
    const plaintext = stringToBytes('Secret');
    const ad1 = stringToBytes('Version: 1');
    const ad2 = stringToBytes('Version: 2');
    
    const ciphertext = aeadEncrypt(plaintext, key, ad1);
    
    expect(() => aeadDecrypt(ciphertext, key, ad2)).toThrow('Authentication failed');
  });

  it('should fail if associated data is missing', () => {
    const key = generateRandomKey();
    const plaintext = stringToBytes('Secret');
    const ad = stringToBytes('Required context');
    
    const ciphertext = aeadEncrypt(plaintext, key, ad);
    
    // Try to decrypt without AD
    expect(() => aeadDecrypt(ciphertext, key)).toThrow('Authentication failed');
  });
});

describe('RandomUniverseCipher AEAD Methods', () => {
  it('should use encryptAuthenticated/decryptAuthenticated', () => {
    const cipher = RandomUniverseCipher.fromPassword('test-password');
    
    const plaintext = 'Authenticated message';
    const ciphertext = cipher.encryptAuthenticated(plaintext);
    const decrypted = cipher.decryptAuthenticatedToString(ciphertext);
    
    expect(decrypted).toBe(plaintext);
  });

  it('should work with associated data via class methods', () => {
    const cipher = RandomUniverseCipher.fromPassword('test-password');
    
    const plaintext = 'Secret payload';
    const ad = 'user-id:12345';
    
    const ciphertext = cipher.encryptAuthenticated(plaintext, ad);
    const decrypted = cipher.decryptAuthenticatedToString(ciphertext, ad);
    
    expect(decrypted).toBe(plaintext);
  });

  it('should detect tampering via class methods', () => {
    const cipher = RandomUniverseCipher.fromPassword('test-password');
    
    const ciphertext = cipher.encryptAuthenticated('Secret');
    
    // Tamper
    const tampered = new Uint8Array(ciphertext);
    tampered[20] ^= 0xff;
    
    expect(() => cipher.decryptAuthenticated(tampered)).toThrow();
  });
});

