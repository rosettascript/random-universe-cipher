/**
 * Random Universe Cipher - Decryption
 * 
 * Block decryption - identical to encryption due to XOR-based keystream
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
 * Order selectors by priority (same as encryption)
 */
function orderSelectors(
  selectors: number[],
  key: Uint8Array,
  iv: Uint8Array,
  blockNumber: bigint
): number[] {
  const blockBytes = bigIntToBytes(blockNumber, 8);
  const seed = shake256Hash(
    concatBytes(key, iv, blockBytes, stringToBytes(DOMAIN.PRIORITY)),
    32
  );
  
  const prng = new ChaCha20PRNG(seed);
  
  const priorities: Array<{ selector: number; priority: number; index: number }> = [];
  for (let j = 0; j < selectors.length; j++) {
    const priority = prng.nextInt(7);
    priorities.push({ selector: selectors[j], priority, index: j });
  }
  
  priorities.sort((a, b) => {
    if (a.priority !== b.priority) return a.priority - b.priority;
    return a.index - b.index;
  });
  
  return priorities.map(p => p.selector);
}

/**
 * Execute a single round (same as encryption)
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
  
  for (const sel of orderedSelectors) {
    const destVal = (state.registers[0] ^ BigInt(sel) ^ roundKey) & MASK.U32;
    const placeIdx = Number(destVal % 7n);
    
    const temp = (sel * 2) & 0xffff;
    const stateByte = Number((state.registers[placeIdx] >> 504n) & 0xffn);
    let gfResult = gfMul(temp & 0xff, stateByte);
    
    const constSeed = shake256Hash(
      concatBytes(key, stringToBytes(DOMAIN.CONSTANT), numberToBytes(sel, 2)),
      1
    );
    const keyConst = constSeed[0];
    gfResult = gfResult ^ keyConst;
    
    const result = sbox[gfResult];
    
    state.registers[placeIdx] = gfMulRegister(state.registers[placeIdx], result);
    
    const shiftAmount = sel % 16;
    state.registers[placeIdx] = xor512(
      state.registers[placeIdx],
      BigInt(result) << BigInt(shiftAmount)
    );
    
    const lowByte = Number(state.registers[placeIdx] & 0xffn);
    const sboxResult = sbox[lowByte];
    state.registers[placeIdx] = xor512(
      state.registers[placeIdx],
      BigInt(sboxResult)
    );
    
    state.registers[placeIdx] = rotateLeft512(state.registers[placeIdx], 1);
    
    state.registers[placeIdx] = xor512(
      state.registers[placeIdx],
      state.registers[(placeIdx + 1) % CONFIG.registerCount]
    );
    
    state.accumulator = add1024(state.accumulator, BigInt(result));
  }
  
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
 * Generate keystream (same as encryption)
 */
function generateKeystream(
  state: CipherState,
  blockNumber: bigint
): Uint8Array {
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
 * Apply ciphertext feedback (same as encryption - uses ciphertext, not plaintext)
 */
function applyCiphertextFeedback(
  state: CipherState,
  ciphertext: Uint8Array
): void {
  const cInt = bytesToBigInt(ciphertext);
  
  for (let i = 0; i < CONFIG.registerCount; i++) {
    const feedbackShift = (i * 37) % 256;
    state.registers[i] = xor512(
      state.registers[i],
      (cInt << BigInt(feedbackShift)) & MASK.U512
    );
  }
}

/**
 * Decrypt a single block
 * 
 * IMPORTANT: Decryption is functionally identical to encryption.
 * This works because:
 * 1. Keystream generation is deterministic (depends only on key, IV, state, block number)
 * 2. XOR is its own inverse: P XOR KS = C, therefore C XOR KS = P
 * 3. State feedback uses ciphertext, which is identical in both operations
 */
export function decryptBlock(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  blockNumber: bigint,
  state: CipherState,
  keyMaterial: KeyMaterial
): Uint8Array {
  if (ciphertext.length !== BYTES.BLOCK) {
    throw new Error(`Ciphertext block must be ${BYTES.BLOCK} bytes`);
  }
  
  // Step 1: Order selectors (same as encrypt)
  const orderedSelectors = orderSelectors(
    keyMaterial.selectors,
    key,
    iv,
    blockNumber
  );
  
  // Step 2: Reset accumulator
  state.accumulator = 0n;
  
  // Step 3: Execute all rounds (same as encrypt)
  for (let r = 0; r < CONFIG.rounds; r++) {
    executeRound(state, r, orderedSelectors, keyMaterial, key);
  }
  
  // Step 4: Generate keystream (same as encrypt)
  const keystream = generateKeystream(state, blockNumber);
  
  // Step 5: XOR ciphertext with keystream to get plaintext
  const plaintext = new Uint8Array(BYTES.BLOCK);
  for (let i = 0; i < BYTES.BLOCK; i++) {
    plaintext[i] = ciphertext[i] ^ keystream[i];
  }
  
  // Step 6: Apply ciphertext feedback (same as encrypt - uses C, not P!)
  applyCiphertextFeedback(state, ciphertext);
  
  return plaintext;
}

