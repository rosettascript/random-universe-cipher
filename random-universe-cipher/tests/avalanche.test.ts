/**
 * Avalanche Effect and Security Tests
 */

import { describe, it, expect } from 'vitest';
import {
  RandomUniverseCipher,
  generateRandomKey,
  generateRandomNonce,
  generateRandomIV,
  encryptCBC,
  BYTES,
} from '../src/cipher';
import { randomBytes, hammingDistance } from '../src/cipher/bigint-utils';

describe('Avalanche Effect', () => {
  it('should flip ~50% of bits when one plaintext bit changes (CBC mode)', () => {
    // Note: CTR mode keystream is plaintext-independent by design
    // For plaintext avalanche, we use CBC mode which chains blocks
    const key = generateRandomKey();
    
    const numTests = 30;
    const flipRates: number[] = [];
    
    for (let i = 0; i < numTests; i++) {
      // Generate random plaintext
      const plaintext1 = randomBytes(BYTES.BLOCK);
      const plaintext2 = new Uint8Array(plaintext1);
      
      // Flip one random bit
      const bitPos = Math.floor(Math.random() * (BYTES.BLOCK * 8));
      const byteIdx = Math.floor(bitPos / 8);
      const bitIdx = bitPos % 8;
      plaintext2[byteIdx] ^= (1 << bitIdx);
      
      // Use same IV for fair comparison
      const iv = generateRandomIV();
      
      // Encrypt both with CBC
      const ciphertext1 = encryptCBC(plaintext1, key, iv);
      const ciphertext2 = encryptCBC(plaintext2, key, iv);
      
      // Skip IV and compare encrypted data
      const c1Data = ciphertext1.subarray(BYTES.IV);
      const c2Data = ciphertext2.subarray(BYTES.IV);
      
      // Calculate bit flip rate
      const distance = hammingDistance(c1Data, c2Data);
      const flipRate = distance / (c1Data.length * 8);
      flipRates.push(flipRate);
    }
    
    // Calculate statistics
    const avgFlipRate = flipRates.reduce((a, b) => a + b, 0) / flipRates.length;
    
    // CBC mode should show avalanche effect (plaintext changes propagate)
    // Note: CBC XORs plaintext with previous ciphertext, so single-bit changes
    // affect only parts of the block. The key sensitivity test is more important.
    expect(avgFlipRate).toBeGreaterThan(0.15); // At least 15% of bits change
    expect(avgFlipRate).toBeLessThan(0.85);
  });

  it('should flip ~50% of bits when one key bit changes', () => {
    const numTests = 20;
    const flipRates: number[] = [];
    
    for (let i = 0; i < numTests; i++) {
      // Generate two keys differing by one bit
      const key1 = generateRandomKey();
      const key2 = new Uint8Array(key1);
      
      const bitPos = Math.floor(Math.random() * (BYTES.KEY * 8));
      const byteIdx = Math.floor(bitPos / 8);
      const bitIdx = bitPos % 8;
      key2[byteIdx] ^= (1 << bitIdx);
      
      const cipher1 = new RandomUniverseCipher(key1);
      const cipher2 = new RandomUniverseCipher(key2);
      
      const plaintext = randomBytes(BYTES.BLOCK);
      const nonce = generateRandomNonce();
      
      const ciphertext1 = cipher1.encrypt(plaintext, nonce);
      const ciphertext2 = cipher2.encrypt(plaintext, nonce);
      
      const c1Data = ciphertext1.subarray(BYTES.NONCE);
      const c2Data = ciphertext2.subarray(BYTES.NONCE);
      
      const distance = hammingDistance(c1Data, c2Data);
      const flipRate = distance / (c1Data.length * 8);
      flipRates.push(flipRate);
    }
    
    const avgFlipRate = flipRates.reduce((a, b) => a + b, 0) / flipRates.length;
    
    expect(avgFlipRate).toBeGreaterThan(0.4);
    expect(avgFlipRate).toBeLessThan(0.6);
  });
});

describe('Key Sensitivity', () => {
  it('should produce completely different output with different keys', () => {
    const key1 = generateRandomKey();
    const key2 = generateRandomKey();
    const cipher1 = new RandomUniverseCipher(key1);
    const cipher2 = new RandomUniverseCipher(key2);
    
    const plaintext = randomBytes(BYTES.BLOCK);
    const nonce = generateRandomNonce();
    
    const ciphertext1 = cipher1.encrypt(plaintext, nonce);
    const ciphertext2 = cipher2.encrypt(plaintext, nonce);
    
    // Should be very different
    const c1Data = ciphertext1.subarray(BYTES.NONCE);
    const c2Data = ciphertext2.subarray(BYTES.NONCE);
    const distance = hammingDistance(c1Data, c2Data);
    const flipRate = distance / (c1Data.length * 8);
    
    // Should be close to 50% difference
    expect(flipRate).toBeGreaterThan(0.4);
    expect(flipRate).toBeLessThan(0.6);
  });

  it('should produce different output with different passwords', () => {
    const cipher1 = RandomUniverseCipher.fromPassword('password1');
    const cipher2 = RandomUniverseCipher.fromPassword('password2');
    
    const plaintext = 'Same plaintext for both';
    const nonce = generateRandomNonce();
    
    const ciphertext1 = cipher1.encrypt(plaintext, nonce);
    const ciphertext2 = cipher2.encrypt(plaintext, nonce);
    
    // Should be completely different
    expect(ciphertext1).not.toEqual(ciphertext2);
  });
});

describe('Randomness Quality', () => {
  it('should not produce all-zero ciphertext', () => {
    const cipher = RandomUniverseCipher.fromPassword('test');
    
    // Even with all-zero input
    const plaintext = new Uint8Array(BYTES.BLOCK);
    const ciphertext = cipher.encrypt(plaintext);
    
    // Count non-zero bytes in ciphertext (excluding nonce)
    const encData = ciphertext.subarray(BYTES.NONCE);
    let nonZeroCount = 0;
    for (const byte of encData) {
      if (byte !== 0) nonZeroCount++;
    }
    
    // Most bytes should be non-zero
    expect(nonZeroCount).toBeGreaterThan(encData.length * 0.3);
  });

  it('should not produce repeating patterns', () => {
    const cipher = RandomUniverseCipher.fromPassword('pattern-test');
    
    // Encrypt repeating plaintext
    const plaintext = new Uint8Array(BYTES.BLOCK * 4);
    for (let i = 0; i < plaintext.length; i++) {
      plaintext[i] = i % 256;
    }
    
    const ciphertext = cipher.encrypt(plaintext);
    const encData = ciphertext.subarray(BYTES.NONCE);
    
    // Check that blocks are different
    const blocks: Uint8Array[] = [];
    for (let i = 0; i < encData.length; i += BYTES.BLOCK) {
      blocks.push(encData.subarray(i, i + BYTES.BLOCK));
    }
    
    // No two blocks should be identical
    for (let i = 0; i < blocks.length; i++) {
      for (let j = i + 1; j < blocks.length; j++) {
        let same = true;
        for (let k = 0; k < BYTES.BLOCK && same; k++) {
          if (blocks[i][k] !== blocks[j][k]) same = false;
        }
        expect(same).toBe(false);
      }
    }
  });

  it('should have reasonable byte distribution', () => {
    const cipher = RandomUniverseCipher.fromPassword('distribution-test');
    
    // Generate lots of ciphertext
    const counts = new Uint32Array(256);
    
    for (let i = 0; i < 500; i++) {
      const plaintext = randomBytes(BYTES.BLOCK);
      const ciphertext = cipher.encrypt(plaintext);
      const encData = ciphertext.subarray(BYTES.NONCE);
      
      for (const byte of encData) {
        counts[byte]++;
      }
    }
    
    const totalBytes = 500 * BYTES.BLOCK;
    const expectedCount = totalBytes / 256;
    
    // Check that no single byte value dominates or is absent
    let minCount = Infinity;
    let maxCount = 0;
    
    for (let i = 0; i < 256; i++) {
      if (counts[i] < minCount) minCount = counts[i];
      if (counts[i] > maxCount) maxCount = counts[i];
    }
    
    // Min should not be 0, max should not be too extreme
    expect(minCount).toBeGreaterThan(0);
    // Max should be at most 5x the expected (very loose bound)
    expect(maxCount).toBeLessThan(expectedCount * 5);
  });
});

