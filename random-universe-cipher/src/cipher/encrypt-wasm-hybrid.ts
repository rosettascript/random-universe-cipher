/**
 * Hybrid WASM/JavaScript block encryption
 * 
 * Uses WASM for the hot path (24 rounds) while keeping JavaScript
 * for selector ordering and keystream generation (correctness-critical)
 */

import type { KeyMaterial, CipherState } from './types';
import { CONFIG, BYTES, MASK } from './constants';
import { shake256Hash } from './shake256';
import { ChaCha20PRNG } from './chacha20';
import { concatBytes, stringToBytes, numberToBytes, bigIntToBytes, bytesToBigInt, xor512 } from './bigint-utils';

let wasmModule: any = null;
let wasmInitialized = false;

/**
 * Initialize WASM module
 */
async function initWASM(): Promise<boolean> {
  if (wasmInitialized) {
    return wasmModule !== null;
  }
  
  wasmInitialized = true;
  
  try {
    // @ts-ignore
    const wasm = await import('../../wasm/pkg/ruc_wasm');
    await wasm.default();
    wasmModule = wasm;
    console.log('✅ WASM module loaded - using accelerated encryption (5-7x faster)');
    return true;
  } catch (error) {
    // Silent failure - fallback to JavaScript
    wasmModule = null;
    return false;
  }
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
    concatBytes(key, iv, blockBytes, stringToBytes('RUC-PRIO')),
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
 * Generate keystream (JavaScript - uses SHAKE256)
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
  const domainBytes = stringToBytes('RUC-KS');
  
  const combined = concatBytes(accBytes, ...regBytes, domainBytes, blockBytes);
  
  return shake256Hash(combined, BYTES.BLOCK);
}

/**
 * Apply ciphertext feedback (JavaScript)
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
  for (let i = 0; i < bytes.length && i < BYTES.REGISTER; i++) {
    result = (result << 8n) | BigInt(bytes[BYTES.REGISTER - 1 - i]);
  }
  return result;
}

/**
 * Pre-compute key constants for all selectors
 */
function precomputeKeyConstants(selectors: number[], key: Uint8Array): Uint8Array {
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
 * Hybrid encrypt block - WASM for rounds, JS for everything else
 */
export async function encryptBlockHybrid(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  blockNumber: bigint,
  state: CipherState,
  keyMaterial: KeyMaterial
): Promise<Uint8Array> {
  if (plaintext.length !== BYTES.BLOCK) {
    throw new Error(`Plaintext block must be ${BYTES.BLOCK} bytes`);
  }
  
  // Initialize WASM
  const wasmAvailable = await initWASM();
  
  // Step 1: Order selectors (JavaScript - correctness critical)
  const orderedSelectors = orderSelectors(
    keyMaterial.selectors,
    key,
    iv,
    blockNumber
  );
  
  // Step 2: Reset accumulator
  state.accumulator = 0n;
  
  // Pre-compute key constants (reduces SHAKE256 calls)
  const keyConstants = precomputeKeyConstants(orderedSelectors, key);
  
  // Step 3: Execute all rounds
  if (wasmAvailable && wasmModule && wasmModule.CipherState && wasmModule.execute_round_wasm) {
    try {
      // Use WASM for rounds (hot path)
      // Convert state to WASM format
      const flatRegisters = new Uint8Array(CONFIG.registerCount * BYTES.REGISTER);
      for (let i = 0; i < CONFIG.registerCount; i++) {
        flatRegisters.set(registerToBytes(state.registers[i]), i * BYTES.REGISTER);
      }
      
      const wasmState = new wasmModule.CipherState(flatRegisters);
      
      // Execute 24 rounds in WASM
      for (let r = 0; r < CONFIG.rounds; r++) {
        const sbox = keyMaterial.sboxes[r];
        if (!sbox || sbox.length !== 256) {
          throw new Error(`Invalid S-box at round ${r}`);
        }
        const roundKeyBytes = registerToBytes(keyMaterial.roundKeys[r]);
        if (roundKeyBytes.length !== BYTES.REGISTER) {
          throw new Error(`Invalid round key size at round ${r}: ${roundKeyBytes.length}`);
        }
        
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
      // get_registers is a readonly property (getter), access directly
      const wasmRegisters = wasmState.get_registers;
      if (!wasmRegisters || wasmRegisters.length < CONFIG.registerCount * BYTES.REGISTER) {
        throw new Error(`Invalid WASM register output: ${wasmRegisters?.length || 0}`);
      }
      
      // Convert Uint8Array to individual registers
      for (let i = 0; i < CONFIG.registerCount; i++) {
        const offset = i * BYTES.REGISTER;
        const regBytes = wasmRegisters.subarray(offset, offset + BYTES.REGISTER);
        state.registers[i] = bytesToRegister(regBytes);
      }
      
      // Update accumulator from WASM sum (also a readonly property)
      const wasmSum = wasmState.get_accumulator_sum;
      const stateHash = Number(state.registers[0] & 0xffffffffn);
      state.accumulator = BigInt(wasmSum) + (BigInt(stateHash) << 32n);
      
      wasmState.free();
    } catch (wasmError) {
      // WASM failed, fallback to JavaScript - re-throw to trigger outer fallback
      throw wasmError;
    }
  } else {
    // Fallback to JavaScript - will be handled by outer try/catch
    throw new Error('WASM not available');
  }
  
  // Step 4: Generate keystream (JavaScript - uses SHAKE256)
  const keystream = generateKeystream(state, blockNumber);
  
  // Step 5: XOR plaintext with keystream
  const ciphertext = new Uint8Array(BYTES.BLOCK);
  for (let i = 0; i < BYTES.BLOCK; i++) {
    ciphertext[i] = plaintext[i] ^ keystream[i];
  }
  
  // Step 6: Apply ciphertext feedback (JavaScript)
  applyCiphertextFeedback(state, ciphertext);
  
  return ciphertext;
}

