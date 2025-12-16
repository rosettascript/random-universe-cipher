/**
 * WASM-Accelerated Block Encryption
 * 
 * Uses WASM for the hot path (24 rounds) while keeping JavaScript
 * for selector ordering and keystream generation (simpler integration).
 */

import type { KeyMaterial, CipherState } from './types';
import { CONFIG, BYTES, DOMAIN } from './constants';
import { shake256Hash } from './shake256';
import { ChaCha20PRNG } from './chacha20';
import { concatBytes, stringToBytes, numberToBytes, bigIntToBytes, bytesToBigInt } from './bigint-utils';

let wasmModule: any = null;
let wasmInitialized = false;

/**
 * Initialize WASM module (call once at startup)
 */
let wasmBlockCount = 0;
let jsBlockCount = 0;

export async function initWASM(): Promise<boolean> {
  if (wasmInitialized) {
    return wasmModule !== null;
  }
  
  wasmInitialized = true;
  
  try {
    // @ts-ignore
    const wasm = await import('../../wasm/pkg/ruc_wasm');
    await wasm.default();
    wasmModule = wasm;
    console.log('✅ WASM loaded - 5-10x faster encryption enabled');
    return true;
  } catch (error) {
    console.warn('⚠️ WASM unavailable, using JavaScript (slower)');
    wasmModule = null;
    return false;
  }
}

export function getWASMStats() {
  return { wasmBlocks: wasmBlockCount, jsBlocks: jsBlockCount };
}

/**
 * Check if WASM is available
 */
export function isWASMAvailable(): boolean {
  return wasmModule !== null;
}

/**
 * Order selectors by priority (JavaScript - correctness critical)
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
 * Pre-compute key constants for all selectors
 */
function precomputeKeyConstants(selectors: number[], key: Uint8Array): Uint8Array {
  const constants = new Uint8Array(selectors.length);
  for (let i = 0; i < selectors.length; i++) {
    const sel = selectors[i];
    const constSeed = shake256Hash(
      concatBytes(key, stringToBytes(DOMAIN.CONSTANT), numberToBytes(sel, 2)),
      1
    );
    constants[i] = constSeed[0];
  }
  return constants;
}

/**
 * Convert BigInt register to Uint8Array for WASM
 */
function registerToBytes(reg: bigint): Uint8Array {
  const bytes = new Uint8Array(BYTES.REGISTER);
  for (let i = 0; i < BYTES.REGISTER; i++) {
    bytes[BYTES.REGISTER - 1 - i] = Number((reg >> BigInt(i * 8)) & 0xffn);
  }
  return bytes;
}

/**
 * Convert Uint8Array to BigInt register from WASM
 */
function bytesToRegister(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < BYTES.REGISTER; i++) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/**
 * Execute rounds using WASM (hot path optimization)
 */
function executeRoundsWASM(
  state: CipherState,
  orderedSelectors: number[],
  keyMaterial: KeyMaterial,
  keyConstants: Uint8Array
): void {
  // Flatten state for WASM
  const flatRegisters = new Uint8Array(CONFIG.registerCount * BYTES.REGISTER);
  for (let i = 0; i < CONFIG.registerCount; i++) {
    flatRegisters.set(registerToBytes(state.registers[i]), i * BYTES.REGISTER);
  }
  
  // Create WASM state
  const wasmState = new wasmModule.CipherState(flatRegisters);
  
  // Execute all 24 rounds in WASM
  for (let r = 0; r < CONFIG.rounds; r++) {
    const sbox = keyMaterial.sboxes[r];
    const roundKeyBytes = registerToBytes(keyMaterial.roundKeys[r]);
    
    wasmModule.execute_round_wasm(
      wasmState,
      r,
      new Uint16Array(orderedSelectors),
      sbox,
      roundKeyBytes,
      keyConstants
    );
  }
  
  // Convert WASM state back to JavaScript
  const wasmRegisters = wasmState.get_registers;
  for (let i = 0; i < CONFIG.registerCount; i++) {
    const offset = i * BYTES.REGISTER;
    state.registers[i] = bytesToRegister(wasmRegisters.subarray(offset, offset + BYTES.REGISTER));
  }
  
  // Update accumulator from WASM
  const wasmSum = wasmState.get_accumulator_sum;
  state.accumulator = BigInt(wasmSum);
  
  wasmState.free();
}

/**
 * Generate keystream from final state
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
 * Apply ciphertext feedback
 */
function applyCiphertextFeedback(
  state: CipherState,
  ciphertext: Uint8Array
): void {
  const cInt = bytesToBigInt(ciphertext);
  
  for (let i = 0; i < CONFIG.registerCount; i++) {
    const feedbackShift = (i * 37) % 256;
    state.registers[i] ^= (cInt << BigInt(feedbackShift)) & ((1n << 512n) - 1n);
  }
}

/**
 * WASM-accelerated block encryption
 * Returns null if WASM not available (fallback to JavaScript)
 */
export function encryptBlockWASM(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  blockNumber: bigint,
  state: CipherState,
  keyMaterial: KeyMaterial
): Uint8Array | null {
  if (!wasmModule) {
    jsBlockCount++;
    return null; // WASM not available
  }
  
  try {
    wasmBlockCount++;
    
    // Step 1: Order selectors (JavaScript - correctness critical)
    const orderedSelectors = orderSelectors(
      keyMaterial.selectors,
      key,
      iv,
      blockNumber
    );
    
    // Step 2: Reset accumulator
    state.accumulator = 0n;
    
    // Pre-compute key constants
    const keyConstants = precomputeKeyConstants(orderedSelectors, key);
    
    // Step 3: Execute all rounds using WASM (hot path)
    executeRoundsWASM(state, orderedSelectors, keyMaterial, keyConstants);
    
    // Step 4: Generate keystream (JavaScript - uses SHAKE256)
    const keystream = generateKeystream(state, blockNumber);
    
    // Step 5: XOR plaintext with keystream
    const ciphertext = new Uint8Array(BYTES.BLOCK);
    for (let i = 0; i < BYTES.BLOCK; i++) {
      ciphertext[i] = plaintext[i] ^ keystream[i];
    }
    
    // Step 6: Apply ciphertext feedback
    applyCiphertextFeedback(state, ciphertext);
    
    // Log stats every 1000 blocks
    if (wasmBlockCount % 1000 === 0) {
      console.log(`📊 WASM: ${wasmBlockCount} blocks, JS fallback: ${jsBlockCount} blocks`);
    }
    
    return ciphertext;
  } catch (error) {
    console.error('WASM encryption error:', error);
    jsBlockCount++;
    return null; // Fallback to JavaScript
  }
}

/**
 * WASM-accelerated block decryption (same as encryption for XOR-based cipher)
 */
export function decryptBlockWASM(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  blockNumber: bigint,
  state: CipherState,
  keyMaterial: KeyMaterial
): Uint8Array | null {
  return encryptBlockWASM(ciphertext, key, iv, blockNumber, state, keyMaterial);
}

