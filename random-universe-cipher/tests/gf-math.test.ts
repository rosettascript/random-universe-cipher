/**
 * GF(2^8) Mathematics Tests
 */

import { describe, it, expect } from 'vitest';
import { gfMul, gfMulRegister, gfInverse, gfPow } from '../src/cipher/gf-math';

describe('GF(2^8) Multiplication', () => {
  it('should return identity when multiplying by 1', () => {
    for (let x = 0; x < 256; x++) {
      expect(gfMul(x, 1)).toBe(x);
    }
  });

  it('should return 0 when multiplying by 0', () => {
    for (let x = 0; x < 256; x++) {
      expect(gfMul(x, 0)).toBe(0);
      expect(gfMul(0, x)).toBe(0);
    }
  });

  it('should be commutative', () => {
    for (let a = 0; a < 256; a += 17) {
      for (let b = 0; b < 256; b += 19) {
        expect(gfMul(a, b)).toBe(gfMul(b, a));
      }
    }
  });

  it('should be associative', () => {
    for (let a = 1; a < 256; a += 31) {
      for (let b = 1; b < 256; b += 37) {
        for (let c = 1; c < 256; c += 41) {
          expect(gfMul(gfMul(a, b), c)).toBe(gfMul(a, gfMul(b, c)));
        }
      }
    }
  });

  it('should produce known AES values', () => {
    // Known test vectors from AES GF(2^8)
    expect(gfMul(0x57, 0x83)).toBe(0xc1);
    expect(gfMul(0x02, 0x87)).toBe(0x15);
    expect(gfMul(0x03, 0x6e)).toBe(0xb2);
  });
});

describe('GF(2^8) Inverse', () => {
  it('should return 0 for input 0', () => {
    expect(gfInverse(0)).toBe(0);
  });

  it('should satisfy a * a^-1 = 1', () => {
    for (let a = 1; a < 256; a++) {
      const inv = gfInverse(a);
      expect(gfMul(a, inv)).toBe(1);
    }
  });
});

describe('GF(2^8) Power', () => {
  it('should return 1 for any number to power 0', () => {
    for (let a = 0; a < 256; a++) {
      expect(gfPow(a, 0)).toBe(1);
    }
  });

  it('should return a for a^1', () => {
    for (let a = 0; a < 256; a++) {
      expect(gfPow(a, 1)).toBe(a);
    }
  });

  it('should satisfy a^255 = 1 for non-zero a (Fermat)', () => {
    for (let a = 1; a < 256; a++) {
      expect(gfPow(a, 255)).toBe(1);
    }
  });
});

describe('GF Register Multiplication', () => {
  it('should multiply each byte independently', () => {
    // Simple test: multiply register with all 0x01 bytes by 2
    const reg = 0x0101010101010101n;
    const result = gfMulRegister(reg, 2);
    expect(result).toBe(0x0202020202020202n);
  });

  it('should handle zero multiplier', () => {
    const reg = 0xffffffffffffffffn;
    const result = gfMulRegister(reg, 0);
    expect(result).toBe(0n);
  });

  it('should handle identity multiplier', () => {
    const reg = 0x123456789abcdef0n;
    const result = gfMulRegister(reg, 1);
    expect(result).toBe(reg);
  });
});

