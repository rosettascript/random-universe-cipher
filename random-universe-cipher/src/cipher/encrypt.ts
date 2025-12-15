/**
 * Random Universe Cipher - Encryption
 * 
 * Block encryption implementing the full 24-round cipher
 */

import type { KeyMaterial, CipherState } from './types';
import { CONFIG, DOMAIN, BYTES, MASK } from './constants';
import { shake256Hash } from './shake256';
import { ChaCha20PRNG } from './chacha20';
import { gfMul, gfMulRegister } from './gf-math';
import {
  bytesToBigInt,
  bigIntToBytes,
  concatBytes,
  stringToBytes,
  numberToBytes,
  rotateLeft512,
  xor512,
  add1024,
} from './bigint-utils';

/**
 * Order selectors by priority for a specific block
 * Uses ChaCha20 seeded with key || IV || block_number
 */
function orderSelectors(
  selectors: number[],
  key: Uint8Array,
  iv: Uint8Array,
  blockNumber: bigint
): number[] {
  // Create seed from key || IV || block_number
  const blockBytes = bigIntToBytes(blockNumber, 8);
  const seed = shake256Hash(
    concatBytes(key, iv, blockBytes, stringToBytes(DOMAIN.PRIORITY)),
    32
  );
  
  const prng = new ChaCha20PRNG(seed);
  
  // Assign priorities
  const priorities: Array<{ selector: number; priority: number; index: number }> = [];
  for (let j = 0; j < selectors.length; j++) {
    const priority = prng.nextInt(7);
    priorities.push({ selector: selectors[j], priority, index: j });
  }
  
  // Stable sort by priority (preserve original order for ties)
  priorities.sort((a, b) => {
    if (a.priority !== b.priority) return a.priority - b.priority;
    return a.index - b.index;
  });
  
  return priorities.map(p => p.selector);
}

/**
 * Execute a single round of the cipher
 */
function executeRound(
  state: CipherState,
  roundIndex: number,
  orderedSelectors: number[],
  keyMaterial: KeyMaterial,
  key: Uint8Array
): void {
  const sbox = keyMaterial.sboxes[roundIndex];
  const roundKey = keyMaterial.roundKeys[roundIndex];
  
  // Process each selector
  for (const sel of orderedSelectors) {
    // Step 1: Select destination register
    // place_idx = (R[0] XOR selector XOR roundKey) mod 7
    const destVal = (state.registers[0] ^ BigInt(sel) ^ roundKey) & MASK.U32;
    const placeIdx = Number(destVal % 7n);
    
    // Step 2: Compute non-linear transformation
    const temp = (sel * 2) & 0xffff;
    
    // Extract top byte from state register for GF multiplication
    const stateByte = Number((state.registers[placeIdx] >> 504n) & 0xffn);
    let gfResult = gfMul(temp & 0xff, stateByte);
    
    // XOR with key-derived constant
    const constSeed = shake256Hash(
      concatBytes(key, stringToBytes(DOMAIN.CONSTANT), numberToBytes(sel, 2)),
      1
    );
    const keyConst = constSeed[0];
    gfResult = gfResult ^ keyConst;
    
    // Apply S-box
    const result = sbox[gfResult];
    
    // Step 3: Update state register (non-linear mixing)
    // GF multiply each byte of register
    state.registers[placeIdx] = gfMulRegister(state.registers[placeIdx], result);
    
    // XOR with shifted result
    const shiftAmount = sel % 16;
    state.registers[placeIdx] = xor512(
      state.registers[placeIdx],
      BigInt(result) << BigInt(shiftAmount)
    );
    
    // Apply S-box to low byte and XOR
    const lowByte = Number(state.registers[placeIdx] & 0xffn);
    const sboxResult = sbox[lowByte];
    state.registers[placeIdx] = xor512(
      state.registers[placeIdx],
      BigInt(sboxResult)
    );
    
    // Rotate left by 1
    state.registers[placeIdx] = rotateLeft512(state.registers[placeIdx], 1);
    
    // Mix with adjacent register
    state.registers[placeIdx] = xor512(
      state.registers[placeIdx],
      state.registers[(placeIdx + 1) % CONFIG.registerCount]
    );
    
    // Step 4: Accumulate result
    state.accumulator = add1024(state.accumulator, BigInt(result));
  }
  
  // Inter-round state mixing
  for (let i = 0; i < CONFIG.registerCount; i++) {
    state.registers[i] = xor512(
      state.registers[i],
      state.registers[(i + 1) % CONFIG.registerCount]
    );
    state.registers[i] = xor512(
      state.registers[i],
      state.registers[(i + 2) % CONFIG.registerCount]
    );
  }
}

/**
 * Generate keystream from the final state
 */
function generateKeystream(
  state: CipherState,
  blockNumber: bigint
): Uint8Array {
  // Combine accumulator and state
  const accBytes = bigIntToBytes(state.accumulator, BYTES.ACCUMULATOR);
  const regBytes: Uint8Array[] = [];
  for (let i = 0; i < CONFIG.registerCount; i++) {
    regBytes.push(bigIntToBytes(state.registers[i], BYTES.REGISTER));
  }
  
  const blockBytes = bigIntToBytes(blockNumber, 8);
  const domainBytes = stringToBytes(DOMAIN.KEYSTREAM);
  
  const combined = concatBytes(accBytes, ...regBytes, domainBytes, blockBytes);
  
  return shake256Hash(combined, BYTES.BLOCK);
}

/**
 * Apply ciphertext feedback to state
 */
function applyCiphertextFeedback(
  state: CipherState,
  ciphertext: Uint8Array
): void {
  const cInt = bytesToBigInt(ciphertext);
  
  for (let i = 0; i < CONFIG.registerCount; i++) {
    const feedbackShift = (i * 37) % 256; // Prime multiplier
    state.registers[i] = xor512(
      state.registers[i],
      (cInt << BigInt(feedbackShift)) & MASK.U512
    );
  }
}

/**
 * Encrypt a single block
 */
export function encryptBlock(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  blockNumber: bigint,
  state: CipherState,
  keyMaterial: KeyMaterial
): Uint8Array {
  if (plaintext.length !== BYTES.BLOCK) {
    throw new Error(`Plaintext block must be ${BYTES.BLOCK} bytes`);
  }
  
  // Step 1: Order selectors for this block
  const orderedSelectors = orderSelectors(
    keyMaterial.selectors,
    key,
    iv,
    blockNumber
  );
  
  // Step 2: Reset accumulator for this block
  state.accumulator = 0n;
  
  // Step 3: Execute all rounds
  for (let r = 0; r < CONFIG.rounds; r++) {
    executeRound(state, r, orderedSelectors, keyMaterial, key);
  }
  
  // Step 4: Generate keystream
  const keystream = generateKeystream(state, blockNumber);
  
  // Step 5: XOR plaintext with keystream
  const ciphertext = new Uint8Array(BYTES.BLOCK);
  for (let i = 0; i < BYTES.BLOCK; i++) {
    ciphertext[i] = plaintext[i] ^ keystream[i];
  }
  
  // Step 6: Apply ciphertext feedback
  applyCiphertextFeedback(state, ciphertext);
  
  return ciphertext;
}

/**
 * Create initial cipher state from key material
 */
export function createCipherState(keyMaterial: KeyMaterial): CipherState {
  return {
    registers: keyMaterial.registers.map(r => r),
    accumulator: 0n,
  };
}

/**
 * Clone cipher state (for independent operations)
 */
export function cloneCipherState(state: CipherState): CipherState {
  return {
    registers: state.registers.map(r => r),
    accumulator: state.accumulator,
  };
}

