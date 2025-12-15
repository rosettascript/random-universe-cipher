/**
 * Password-based Encryption Tests (with auto-bundled salt)
 */

import { describe, it, expect } from 'vitest';
import {
  encryptWithPassword,
  decryptWithPassword,
  decryptWithPasswordToString,
  encryptWithPasswordAEAD,
  decryptWithPasswordAEAD,
  decryptWithPasswordAEADToString,
  secureEncrypt,
  secureDecrypt,
} from '../src/cipher';

describe('Password Encryption (auto-bundled salt)', () => {
  it('should encrypt and decrypt with bundled salt', async () => {
    const plaintext = 'Hello, password encryption!';
    const password = 'my-secure-password';
    
    const encrypted = await encryptWithPassword(plaintext, password);
    const decrypted = await decryptWithPasswordToString(encrypted, password);
    
    expect(decrypted).toBe(plaintext);
  });

  it('should work with different passwords producing different ciphertexts', async () => {
    const plaintext = 'Same message';
    
    const encrypted1 = await encryptWithPassword(plaintext, 'password1');
    const encrypted2 = await encryptWithPassword(plaintext, 'password2');
    
    // Different passwords = different salts and keys = different ciphertexts
    expect(encrypted1).not.toEqual(encrypted2);
  });

  it('should fail decryption with wrong password', async () => {
    const encrypted = await encryptWithPassword('Secret', 'correct-password');
    
    // Wrong password should fail (padding error since key is wrong)
    await expect(
      decryptWithPassword(encrypted, 'wrong-password')
    ).rejects.toThrow();
  });

  it('should include salt in output (first 16 bytes)', async () => {
    const encrypted = await encryptWithPassword('Test', 'password');
    
    // Output should be: salt (16) + nonce (16) + ciphertext (>=32)
    expect(encrypted.length).toBeGreaterThanOrEqual(16 + 16 + 32);
  });
});

describe('Password AEAD Encryption (authenticated + auto-bundled salt)', () => {
  it('should encrypt and decrypt with authentication', async () => {
    const plaintext = 'Authenticated message';
    const password = 'secure-password';
    
    const encrypted = await encryptWithPasswordAEAD(plaintext, password);
    const decrypted = await decryptWithPasswordAEADToString(encrypted, password);
    
    expect(decrypted).toBe(plaintext);
  });

  it('should detect tampering', async () => {
    const encrypted = await encryptWithPasswordAEAD('Secret', 'password');
    
    // Tamper with the encrypted data (after salt)
    const tampered = new Uint8Array(encrypted);
    tampered[20] ^= 0xff;
    
    await expect(
      decryptWithPasswordAEAD(tampered, 'password')
    ).rejects.toThrow('Authentication failed');
  });

  it('should fail with wrong password (authentication error)', async () => {
    const encrypted = await encryptWithPasswordAEAD('Secret', 'correct-password');
    
    await expect(
      decryptWithPasswordAEAD(encrypted, 'wrong-password')
    ).rejects.toThrow('Authentication failed');
  });

  it('should work with associated data', async () => {
    const plaintext = 'Secret payload';
    const password = 'password';
    const ad = 'user-id:12345';
    
    const encrypted = await encryptWithPasswordAEAD(plaintext, password, ad);
    const decrypted = await decryptWithPasswordAEADToString(encrypted, password, ad);
    
    expect(decrypted).toBe(plaintext);
  });

  it('should fail if associated data differs', async () => {
    const encrypted = await encryptWithPasswordAEAD('Secret', 'password', 'context-1');
    
    await expect(
      decryptWithPasswordAEAD(encrypted, 'password', 'context-2')
    ).rejects.toThrow('Authentication failed');
  });
});

describe('secureEncrypt/secureDecrypt (recommended API)', () => {
  it('should be the simplest way to encrypt', async () => {
    const message = 'This is the easiest way to encrypt! 🔐';
    const password = 'my-password';
    
    // Encrypt returns base64 string
    const encrypted = await secureEncrypt(message, password);
    expect(typeof encrypted).toBe('string');
    
    // Decrypt from base64 string
    const decrypted = await secureDecrypt(encrypted, password);
    expect(decrypted).toBe(message);
  });

  it('should handle unicode and emojis', async () => {
    const message = '日本語テスト 🎉🔒💪';
    const password = 'パスワード';
    
    const encrypted = await secureEncrypt(message, password);
    const decrypted = await secureDecrypt(encrypted, password);
    
    expect(decrypted).toBe(message);
  });

  it('should work with empty string', async () => {
    const encrypted = await secureEncrypt('', 'password');
    const decrypted = await secureDecrypt(encrypted, 'password');
    
    expect(decrypted).toBe('');
  });

  it('should produce different ciphertext each time (random salt + nonce)', async () => {
    const message = 'Same message';
    const password = 'same-password';
    
    const encrypted1 = await secureEncrypt(message, password);
    const encrypted2 = await secureEncrypt(message, password);
    
    // Random salt and nonce means different output each time
    expect(encrypted1).not.toBe(encrypted2);
    
    // But both should decrypt to same plaintext
    expect(await secureDecrypt(encrypted1, password)).toBe(message);
    expect(await secureDecrypt(encrypted2, password)).toBe(message);
  });
});

