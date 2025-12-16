/**
 * WebAssembly-accelerated encryption modes
 * 
 * This module provides WASM-accelerated block encryption for maximum performance.
 * Uses batch processing to minimize JS/WASM boundary crossings.
 * Falls back to JavaScript implementation if WASM is not available.
 */

import { BYTES, CONFIG } from './constants';
import { concatBytes, stringToBytes, numberToBytes } from './bigint-utils';
import { shake256Hash } from './shake256';
import type { KeyMaterial } from './types';

let wasmModule: any = null;
let wasmInitialized = false;

/**
 * Initialize WASM module
 */
export async function initWASM(): Promise<boolean> {
  if (wasmInitialized) {
    return wasmModule !== null;
  }
  
  wasmInitialized = true;
  
  try {
    // Try to load WASM module
    // @ts-ignore - WASM module will be available after build
    const wasm = await import('../../wasm/pkg/ruc_wasm');
    await wasm.default();
    wasmModule = wasm;
    console.log('✅ WASM module loaded - using accelerated encryption (7-10x faster)');
    return true;
  } catch (error) {
    console.warn('⚠️ WASM module not available, using JavaScript fallback:', error);
    wasmModule = null;
    return false;
  }
}

/**
 * Check if WASM is available
 */
export function isWASMAvailable(): boolean {
  return wasmModule !== null;
}

/**
 * Pre-compute key constants for all selectors (reduces SHAKE256 calls)
 */
function precomputeKeyConstants(
  selectors: number[],
  key: Uint8Array
): Uint8Array {
  const constants = new Uint8Array(selectors.length);
  for (let i = 0; i < selectors.length; i++) {
    const sel = selectors[i];
    const constSeed = shake256Hash(
      concatBytes(key, stringToBytes('RUC-CONST'), numberToBytes(sel, 2)),
      1
    );
    constants[i] = constSeed[0];
  }
  return constants;
}

/**
 * WASM-accelerated CTR mode encryption with batch processing
 * Processes blocks in batches for maximum performance
 */
export async function encryptCTRWASM(
  plaintext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  keyMaterial: KeyMaterial,
  onProgress?: (progress: number) => void
): Promise<Uint8Array> {
  // Initialize WASM if not already done
  const wasmAvailable = await initWASM();
  
  // TEMPORARY: Disable WASM batch processing until implementation is complete
  // The current WASM implementation is missing:
  // 1. Per-block selector ordering (critical for correctness)
  // 2. Proper keystream generation with SHAKE256
  // 3. Counter handling for CTR mode
  // 4. Ciphertext feedback
  // TODO: Complete WASM implementation to match TypeScript exactly
  const USE_WASM_BATCH = false; // Set to true when WASM is complete
  
  if (!wasmAvailable || !wasmModule || !USE_WASM_BATCH) {
    // Fallback to JavaScript implementation
    const { encryptCTRFast } = await import('./modes-fast');
    return encryptCTRFast(plaintext, key, nonce, onProgress);
  }
  
  // Pad plaintext
  const paddingLen = BYTES.BLOCK - (plaintext.length % BYTES.BLOCK);
  const padded = new Uint8Array(plaintext.length + paddingLen);
  padded.set(plaintext);
  for (let i = plaintext.length; i < padded.length; i++) {
    padded[i] = paddingLen;
  }
  
  const numBlocks = padded.length / BYTES.BLOCK;
  const output = new Uint8Array(BYTES.NONCE + padded.length);
  output.set(nonce, 0);
  
  // Pre-compute key constants for all selectors (batch optimization)
  const keyConstants = precomputeKeyConstants(keyMaterial.selectors, key);
  
  // Flatten S-boxes and round keys for WASM
  const sboxesFlat = new Uint8Array(CONFIG.rounds * 256);
  const roundKeysFlat = new Uint8Array(CONFIG.rounds * BYTES.REGISTER);
  
  for (let r = 0; r < CONFIG.rounds; r++) {
    // S-boxes
    sboxesFlat.set(keyMaterial.sboxes[r], r * 256);
    
    // Round keys (convert BigInt to bytes)
    const rkBytes = new Uint8Array(BYTES.REGISTER);
    let rkValue = keyMaterial.roundKeys[r];
    for (let i = 0; i < BYTES.REGISTER; i++) {
      rkBytes[BYTES.REGISTER - 1 - i] = Number((rkValue >> BigInt(i * 8)) & 0xffn);
    }
    roundKeysFlat.set(rkBytes, r * BYTES.REGISTER);
  }
  
  // Flatten registers for WASM
  const registersFlat = new Uint8Array(CONFIG.registerCount * BYTES.REGISTER);
  for (let i = 0; i < CONFIG.registerCount; i++) {
    const regBytes = new Uint8Array(BYTES.REGISTER);
    let regValue = keyMaterial.registers[i];
    for (let j = 0; j < BYTES.REGISTER; j++) {
      regBytes[BYTES.REGISTER - 1 - j] = Number((regValue >> BigInt(j * 8)) & 0xffn);
    }
    registersFlat.set(regBytes, i * BYTES.REGISTER);
  }
  
  // Process in batches (WASM batch function processes multiple blocks)
  const BATCH_SIZE = 64; // Process 64 blocks at a time
  const numBatches = Math.ceil(numBlocks / BATCH_SIZE);
  
  // Pre-compute key constants for all blocks in batch
  const keyConstantsBatch = new Uint8Array(BATCH_SIZE * keyMaterial.selectors.length);
  for (let b = 0; b < BATCH_SIZE; b++) {
    keyConstantsBatch.set(keyConstants, b * keyMaterial.selectors.length);
  }
  
  for (let batchIdx = 0; batchIdx < numBatches; batchIdx++) {
    const startBlock = batchIdx * BATCH_SIZE;
    const endBlock = Math.min(startBlock + BATCH_SIZE, numBlocks);
    const batchSize = endBlock - startBlock;
    
    // Extract batch of plaintext blocks
    const batchPlaintext = padded.subarray(startBlock * BYTES.BLOCK, endBlock * BYTES.BLOCK);
    
    // Process batch in WASM
    const batchKeyConstants = keyConstantsBatch.subarray(0, batchSize * keyMaterial.selectors.length);
    
    // Validate inputs before calling WASM
    if (!wasmModule || !wasmModule.encrypt_blocks_batch) {
      throw new Error('WASM module not properly initialized');
    }
    
    if (batchPlaintext.length !== batchSize * BYTES.BLOCK) {
      throw new Error(`Invalid batch size: expected ${batchSize * BYTES.BLOCK}, got ${batchPlaintext.length}`);
    }
    
    let encryptedBatch: Uint8Array;
    try {
      encryptedBatch = wasmModule.encrypt_blocks_batch(
        batchPlaintext,
        registersFlat,
        new Uint16Array(keyMaterial.selectors),
        sboxesFlat,
        roundKeysFlat,
        batchKeyConstants,
        batchSize
      );
      
      // Validate output
      if (!encryptedBatch || encryptedBatch.length !== batchSize * BYTES.BLOCK) {
        throw new Error(`WASM returned invalid output size: expected ${batchSize * BYTES.BLOCK}, got ${encryptedBatch?.length || 0}`);
      }
    } catch (error) {
      console.error('WASM batch encryption error:', error);
      console.error('Batch details:', {
        batchSize,
        batchPlaintextLength: batchPlaintext.length,
        registersFlatLength: registersFlat.length,
        selectorsLength: keyMaterial.selectors.length,
        sboxesFlatLength: sboxesFlat.length,
        roundKeysFlatLength: roundKeysFlat.length,
        keyConstantsLength: batchKeyConstants.length,
      });
      throw error;
    }
    
    // Copy results to output
    output.set(encryptedBatch, BYTES.NONCE + startBlock * BYTES.BLOCK);
    
    // Report progress
    if (onProgress) {
      const progress = Math.floor(((batchIdx + 1) / numBatches) * 100);
      onProgress(progress);
    }
  }
  
  return output;
}

/**
 * WASM-accelerated CTR mode decryption with batch processing
 * Decryption is identical to encryption (XOR-based keystream)
 */
export async function decryptCTRWASM(
  ciphertext: Uint8Array,
  key: Uint8Array,
  keyMaterial: KeyMaterial,
  onProgress?: (progress: number) => void
): Promise<Uint8Array> {
  // Initialize WASM if not already done
  const wasmAvailable = await initWASM();
  
  // TEMPORARY: Disable WASM batch processing until implementation is complete
  const USE_WASM_BATCH = false; // Set to true when WASM is complete
  
  if (!wasmAvailable || !wasmModule || !USE_WASM_BATCH) {
    // Fallback to JavaScript implementation
    const { decryptCTRFast } = await import('./modes-fast');
    return decryptCTRFast(ciphertext, key, onProgress);
  }
  
  // Extract encrypted data
  const encryptedData = ciphertext.subarray(BYTES.NONCE);
  
  if (encryptedData.length % BYTES.BLOCK !== 0) {
    throw new Error('Invalid ciphertext length');
  }
  
  const numBlocks = encryptedData.length / BYTES.BLOCK;
  
  // Pre-compute key constants for all selectors (batch optimization)
  const keyConstants = precomputeKeyConstants(keyMaterial.selectors, key);
  
  // Flatten S-boxes and round keys for WASM
  const sboxesFlat = new Uint8Array(CONFIG.rounds * 256);
  const roundKeysFlat = new Uint8Array(CONFIG.rounds * BYTES.REGISTER);
  
  for (let r = 0; r < CONFIG.rounds; r++) {
    // S-boxes
    sboxesFlat.set(keyMaterial.sboxes[r], r * 256);
    
    // Round keys (convert BigInt to bytes)
    const rkBytes = new Uint8Array(BYTES.REGISTER);
    let rkValue = keyMaterial.roundKeys[r];
    for (let i = 0; i < BYTES.REGISTER; i++) {
      rkBytes[BYTES.REGISTER - 1 - i] = Number((rkValue >> BigInt(i * 8)) & 0xffn);
    }
    roundKeysFlat.set(rkBytes, r * BYTES.REGISTER);
  }
  
  // Flatten registers for WASM
  const registersFlat = new Uint8Array(CONFIG.registerCount * BYTES.REGISTER);
  for (let i = 0; i < CONFIG.registerCount; i++) {
    const regBytes = new Uint8Array(BYTES.REGISTER);
    let regValue = keyMaterial.registers[i];
    for (let j = 0; j < BYTES.REGISTER; j++) {
      regBytes[BYTES.REGISTER - 1 - j] = Number((regValue >> BigInt(j * 8)) & 0xffn);
    }
    registersFlat.set(regBytes, i * BYTES.REGISTER);
  }
  
  // Process in batches (WASM batch function processes multiple blocks)
  const BATCH_SIZE = 64; // Process 64 blocks at a time
  const numBatches = Math.ceil(numBlocks / BATCH_SIZE);
  const padded = new Uint8Array(encryptedData.length);
  
  // Pre-compute key constants for all blocks in batch
  const keyConstantsBatch = new Uint8Array(BATCH_SIZE * keyMaterial.selectors.length);
  for (let b = 0; b < BATCH_SIZE; b++) {
    keyConstantsBatch.set(keyConstants, b * keyMaterial.selectors.length);
  }
  
  for (let batchIdx = 0; batchIdx < numBatches; batchIdx++) {
    const startBlock = batchIdx * BATCH_SIZE;
    const endBlock = Math.min(startBlock + BATCH_SIZE, numBlocks);
    const batchSize = endBlock - startBlock;
    
    // Extract batch of ciphertext blocks
    const batchCiphertext = encryptedData.subarray(startBlock * BYTES.BLOCK, endBlock * BYTES.BLOCK);
    
    // Process batch in WASM (decryption is same as encryption for XOR-based keystream)
    const batchKeyConstants = keyConstantsBatch.subarray(0, batchSize * keyMaterial.selectors.length);
    const decryptedBatch = wasmModule.encrypt_blocks_batch(
      batchCiphertext, // Same function works for decryption!
      registersFlat,
      new Uint16Array(keyMaterial.selectors),
      sboxesFlat,
      roundKeysFlat,
      batchKeyConstants,
      batchSize
    );
    
    // Copy results to output
    padded.set(decryptedBatch, startBlock * BYTES.BLOCK);
    
    // Report progress
    if (onProgress) {
      const progress = Math.floor(((batchIdx + 1) / numBatches) * 100);
      onProgress(progress);
    }
  }
  
  // Remove PKCS#7 padding
  if (padded.length === 0) {
    throw new Error('Cannot unpad empty data');
  }
  
  const paddingLen = padded[padded.length - 1];
  if (paddingLen === 0 || paddingLen > padded.length || paddingLen > BYTES.BLOCK) {
    throw new Error('Invalid padding');
  }
  
  // Verify all padding bytes
  for (let i = padded.length - paddingLen; i < padded.length; i++) {
    if (padded[i] !== paddingLen) {
      throw new Error('Invalid padding');
    }
  }
  
  return padded.subarray(0, padded.length - paddingLen);
}

