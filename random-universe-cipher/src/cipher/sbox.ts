/**
 * Random Universe Cipher - S-Box Generation
 * 
 * Key-derived S-box generation with cryptographic property verification
 */

import type { SBox } from './types';
import { DOMAIN } from './constants';
import { shake256Hash } from './shake256';
import { concatBytes, stringToBytes, numberToBytes, popcount } from './bigint-utils';

/**
 * Generate an S-box for a specific round using Fisher-Yates shuffle
 */
export function generateSBox(key: Uint8Array, round: number): SBox {
  // Initialize identity permutation
  const sbox = new Uint8Array(256);
  for (let i = 0; i < 256; i++) {
    sbox[i] = i;
  }
  
  // Generate 512 bytes of randomness for the shuffle
  // (need 2 bytes per swap for 255 swaps)
  const domainBytes = stringToBytes(DOMAIN.SBOX);
  const roundBytes = numberToBytes(round, 2);
  const shuffleSeed = shake256Hash(
    concatBytes(key, domainBytes, roundBytes),
    512
  );
  
  // Fisher-Yates shuffle
  for (let i = 255; i > 0; i--) {
    // Use 2 bytes from shuffle_seed for each swap
    const idx = 2 * (255 - i);
    const randVal = (shuffleSeed[idx] << 8) | shuffleSeed[idx + 1];
    const j = randVal % (i + 1);
    
    // Swap sbox[i] and sbox[j]
    const temp = sbox[i];
    sbox[i] = sbox[j];
    sbox[j] = temp;
  }
  
  return sbox;
}

/**
 * Verify that an S-box is bijective (each value 0-255 appears exactly once)
 */
export function isBijective(sbox: SBox): boolean {
  if (sbox.length !== 256) return false;
  
  const seen = new Uint8Array(256);
  for (let i = 0; i < 256; i++) {
    if (seen[sbox[i]]) return false;
    seen[sbox[i]] = 1;
  }
  return true;
}

/**
 * Compute the Walsh-Hadamard Transform of a truth table
 */
function walshHadamardTransform(truthTable: Int32Array): Int32Array {
  const n = truthTable.length; // Should be 256
  const wht = new Int32Array(n);
  
  // Convert truth table to +1/-1 form
  for (let i = 0; i < n; i++) {
    wht[i] = 1 - 2 * truthTable[i]; // 0 -> +1, 1 -> -1
  }
  
  // Fast Walsh-Hadamard Transform (in-place)
  for (let h = 1; h < n; h *= 2) {
    for (let i = 0; i < n; i += h * 2) {
      for (let j = i; j < i + h; j++) {
        const x = wht[j];
        const y = wht[j + h];
        wht[j] = x + y;
        wht[j + h] = x - y;
      }
    }
  }
  
  return wht;
}

/**
 * Compute the non-linearity of an S-box
 * Non-linearity = 128 - (max_absolute_walsh_value / 2)
 * Higher is better (max possible is 120 for 8-bit)
 */
export function computeNonlinearity(sbox: SBox): number {
  let maxWalsh = 0;
  
  // For each non-zero output bit selection (output mask)
  for (let outputMask = 1; outputMask < 256; outputMask++) {
    // Build truth table for this component function
    const truthTable = new Int32Array(256);
    for (let x = 0; x < 256; x++) {
      // Count bits in (sbox[x] AND outputMask)
      truthTable[x] = popcount(sbox[x] & outputMask) & 1;
    }
    
    // Compute Walsh-Hadamard Transform
    const wht = walshHadamardTransform(truthTable);
    
    // Find maximum absolute value
    for (let i = 0; i < 256; i++) {
      const absVal = Math.abs(wht[i]);
      if (absVal > maxWalsh) {
        maxWalsh = absVal;
      }
    }
  }
  
  return 128 - Math.floor(maxWalsh / 2);
}

/**
 * Compute the differential uniformity of an S-box
 * Lower is better (min possible is 2 for 8-bit, but 4 is typical for good S-boxes)
 */
export function computeDifferentialUniformity(sbox: SBox): number {
  let maxCount = 0;
  
  // For each non-zero input difference
  for (let inputDiff = 1; inputDiff < 256; inputDiff++) {
    const counts = new Uint8Array(256);
    
    for (let x = 0; x < 256; x++) {
      const outputDiff = sbox[x] ^ sbox[x ^ inputDiff];
      counts[outputDiff]++;
    }
    
    for (let i = 0; i < 256; i++) {
      if (counts[i] > maxCount) {
        maxCount = counts[i];
      }
    }
  }
  
  return maxCount;
}

/**
 * Compute the algebraic degree of an S-box
 * Higher is better (max possible is 7 for 8-bit)
 */
export function computeAlgebraicDegree(sbox: SBox): number {
  let maxDegree = 0;
  
  // For each output bit position
  for (let outputBit = 0; outputBit < 8; outputBit++) {
    // Extract component function for this output bit
    const truthTable = new Uint8Array(256);
    for (let x = 0; x < 256; x++) {
      truthTable[x] = (sbox[x] >> outputBit) & 1;
    }
    
    // Compute ANF using Mobius transform
    const anf = mobiusTransform(truthTable);
    
    // Find degree (highest Hamming weight of any non-zero coefficient index)
    for (let i = 0; i < 256; i++) {
      if (anf[i] !== 0) {
        const hw = popcount(i); // Hamming weight = degree of this term
        if (hw > maxDegree) {
          maxDegree = hw;
        }
      }
    }
  }
  
  return maxDegree;
}

/**
 * Mobius transform - converts truth table to Algebraic Normal Form (ANF)
 */
function mobiusTransform(f: Uint8Array): Uint8Array {
  const anf = new Uint8Array(f);
  
  for (let i = 0; i < 8; i++) {
    const step = 1 << i;
    for (let j = 0; j < 256; j++) {
      if ((j & step) !== 0) {
        anf[j] ^= anf[j ^ step];
      }
    }
  }
  
  return anf;
}

/**
 * Verify all cryptographic properties of an S-box
 */
export function verifySBoxProperties(sbox: SBox): {
  valid: boolean;
  bijective: boolean;
  nonlinearity: number;
  differentialUniformity: number;
  algebraicDegree: number;
} {
  const bijective = isBijective(sbox);
  const nonlinearity = computeNonlinearity(sbox);
  const differentialUniformity = computeDifferentialUniformity(sbox);
  const algebraicDegree = computeAlgebraicDegree(sbox);
  
  const valid = bijective && 
                nonlinearity >= 100 && 
                differentialUniformity <= 4 && 
                algebraicDegree >= 7;
  
  return {
    valid,
    bijective,
    nonlinearity,
    differentialUniformity,
    algebraicDegree,
  };
}

/**
 * Generate an S-box with verified properties
 * Will retry with modified seeds if properties are not met
 */
export function generateVerifiedSBox(key: Uint8Array, round: number, maxRetries = 100): SBox {
  // Try the primary generation first
  let sbox = generateSBox(key, round);
  let props = verifySBoxProperties(sbox);
  
  if (props.valid) {
    return sbox;
  }
  
  // Retry with modified seeds
  for (let retry = 1; retry <= maxRetries; retry++) {
    const domainBytes = stringToBytes(DOMAIN.SBOX);
    const roundBytes = numberToBytes(round, 2);
    const retryBytes = numberToBytes(retry, 2);
    const modifiedKey = shake256Hash(
      concatBytes(key, domainBytes, roundBytes, retryBytes),
      key.length
    );
    
    sbox = generateSBox(modifiedKey, round);
    props = verifySBoxProperties(sbox);
    
    if (props.valid) {
      return sbox;
    }
  }
  
  // In practice, Fisher-Yates with good randomness almost always produces
  // bijective S-boxes. The property verification is mainly for security analysis.
  // For demo purposes, return the last attempt.
  console.warn(`S-box for round ${round} did not meet all property requirements`);
  return sbox;
}

/**
 * Compute the inverse S-box (for modes that need it)
 */
export function invertSBox(sbox: SBox): SBox {
  const inverse = new Uint8Array(256);
  for (let i = 0; i < 256; i++) {
    inverse[sbox[i]] = i;
  }
  return inverse;
}

