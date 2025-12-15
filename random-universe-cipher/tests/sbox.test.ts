/**
 * S-Box Generation Tests
 */

import { describe, it, expect } from 'vitest';
import {
  generateSBox,
  isBijective,
  computeNonlinearity,
  computeDifferentialUniformity,
  computeAlgebraicDegree,
  verifySBoxProperties,
} from '../src/cipher/sbox';
import { randomBytes } from '../src/cipher/bigint-utils';

describe('S-Box Generation', () => {
  it('should generate a 256-byte S-box', () => {
    const key = randomBytes(64);
    const sbox = generateSBox(key, 0);
    expect(sbox.length).toBe(256);
  });

  it('should be bijective (all values 0-255 appear exactly once)', () => {
    const key = randomBytes(64);
    const sbox = generateSBox(key, 0);
    expect(isBijective(sbox)).toBe(true);
  });

  it('should produce different S-boxes for different rounds', () => {
    const key = randomBytes(64);
    const sbox0 = generateSBox(key, 0);
    const sbox1 = generateSBox(key, 1);
    
    let differences = 0;
    for (let i = 0; i < 256; i++) {
      if (sbox0[i] !== sbox1[i]) differences++;
    }
    
    // Should be significantly different
    expect(differences).toBeGreaterThan(200);
  });

  it('should produce different S-boxes for different keys', () => {
    const key1 = randomBytes(64);
    const key2 = randomBytes(64);
    const sbox1 = generateSBox(key1, 0);
    const sbox2 = generateSBox(key2, 0);
    
    let differences = 0;
    for (let i = 0; i < 256; i++) {
      if (sbox1[i] !== sbox2[i]) differences++;
    }
    
    expect(differences).toBeGreaterThan(200);
  });

  it('should be deterministic (same key + round = same S-box)', () => {
    const key = randomBytes(64);
    const sbox1 = generateSBox(key, 5);
    const sbox2 = generateSBox(key, 5);
    
    for (let i = 0; i < 256; i++) {
      expect(sbox1[i]).toBe(sbox2[i]);
    }
  });
});

describe('S-Box Cryptographic Properties', () => {
  it('should have non-linearity >= 90 (relaxed for random S-boxes)', () => {
    const key = randomBytes(64);
    const sbox = generateSBox(key, 0);
    const nl = computeNonlinearity(sbox);
    
    // Random S-boxes typically have NL around 94-100
    expect(nl).toBeGreaterThanOrEqual(90);
  });

  it('should have differential uniformity <= 16 (relaxed)', () => {
    const key = randomBytes(64);
    const sbox = generateSBox(key, 0);
    const du = computeDifferentialUniformity(sbox);
    
    // Random bijective S-boxes typically have DU 6-12
    expect(du).toBeLessThanOrEqual(16);
  });

  it('should have algebraic degree >= 6', () => {
    const key = randomBytes(64);
    const sbox = generateSBox(key, 0);
    const degree = computeAlgebraicDegree(sbox);
    
    // Random S-boxes almost always have degree 7 or 8
    expect(degree).toBeGreaterThanOrEqual(6);
  });
});

describe('S-Box Property Verification', () => {
  it('should verify all properties together', () => {
    const key = randomBytes(64);
    const sbox = generateSBox(key, 0);
    const props = verifySBoxProperties(sbox);
    
    expect(props.bijective).toBe(true);
    expect(props.nonlinearity).toBeGreaterThan(0);
    expect(props.differentialUniformity).toBeGreaterThan(0);
    expect(props.algebraicDegree).toBeGreaterThan(0);
  });

  it('should detect non-bijective S-box', () => {
    // Create a non-bijective "S-box"
    const badSbox = new Uint8Array(256);
    badSbox.fill(42); // All same value
    
    expect(isBijective(badSbox)).toBe(false);
  });
});

