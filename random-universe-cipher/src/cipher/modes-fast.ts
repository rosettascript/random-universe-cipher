/**
 * Random Universe Cipher - Fast Block Cipher Modes
 * 
 * Optimized implementations with chunked processing and parallelization
 * for fast file encryption/decryption
 */

import { BYTES, DOMAIN } from './constants';
import { expandKey, mixIVIntoState } from './key-expansion';
import { encryptBlock, createCipherState } from './encrypt';
import { decryptBlock } from './decrypt';
import { shake256Hash } from './shake256';
import { concatBytes, stringToBytes, randomBytes, bytesToBigInt } from './bigint-utils';
import { encryptBlockWASM, decryptBlockWASM, initWASM } from './wasm-accelerated';

/**
 * Chunk size for processing (process this many blocks in parallel)
 * Larger = more parallelization but higher memory usage
 * 
 * Adaptive chunk sizes (optimized for performance):
 * - Small files (< 1MB): 128 blocks (4KB chunks)
 * - Medium files (1-50MB): 2048 blocks (64KB chunks) - MUCH larger for speed
 * - Large files (> 50MB, e.g., videos): 4096 blocks (128KB chunks)
 */
function getChunkSize(fileSize: number): number {
  if (fileSize < 1024 * 1024) {
    // Small files: 128 blocks = 4KB
    return 128;
  } else if (fileSize < 50 * 1024 * 1024) {
    // Medium files (15MB videos): 2048 blocks = 64KB chunks
    // This reduces chunk count from ~1920 to ~120 for a 15MB file
    return 2048;
  } else {
    // Large files (videos): 4096 blocks = 128KB chunks
    return 4096;
  }
}

/**
 * How often to yield to event loop (every N chunks)
 * For larger files, yield less frequently to improve performance
 */
function getYieldInterval(fileSize: number): number {
  if (fileSize < 1024 * 1024) {
    return 1; // Yield every chunk for small files
  } else if (fileSize < 50 * 1024 * 1024) {
    return 5; // Yield every 5 chunks for medium files (15MB)
  } else {
    return 10; // Yield every 10 chunks for large files
  }
}

/**
 * Yield to event loop to keep UI responsive
 */
function yieldToMain(): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, 0));
}

/**
 * PKCS#7 padding
 */
function pkcs7Pad(data: Uint8Array, blockSize: number): Uint8Array {
  const paddingLen = blockSize - (data.length % blockSize);
  const padded = new Uint8Array(data.length + paddingLen);
  padded.set(data);
  for (let i = data.length; i < padded.length; i++) {
    padded[i] = paddingLen;
  }
  return padded;
}

/**
 * Remove PKCS#7 padding
 */
function pkcs7Unpad(data: Uint8Array): Uint8Array {
  if (data.length === 0) {
    throw new Error('Cannot unpad empty data');
  }
  
  const paddingLen = data[data.length - 1];
  
  if (paddingLen === 0 || paddingLen > data.length || paddingLen > BYTES.BLOCK) {
    throw new Error('Invalid padding');
  }
  
  // Verify all padding bytes
  for (let i = data.length - paddingLen; i < data.length; i++) {
    if (data[i] !== paddingLen) {
      throw new Error('Invalid padding');
    }
  }
  
  return data.subarray(0, data.length - paddingLen);
}

/**
 * Process a chunk of blocks with WASM acceleration
 * Falls back to JavaScript if WASM unavailable
 */
function processChunk(
  blocks: Uint8Array[],
  startBlockIndex: number,
  key: Uint8Array,
  iv: Uint8Array,
  keyMaterial: ReturnType<typeof expandKey>,
  encrypt: boolean
): Uint8Array[] {
  const results: Uint8Array[] = new Array(blocks.length);
  
  // Process each block (WASM if available, JavaScript fallback)
  for (let i = 0; i < blocks.length; i++) {
    // Create fresh state for each block
    const state = createCipherState(keyMaterial);
    
    // Mix IV into state (CTR mode requirement)
    mixIVIntoState(state.registers, iv);
    
    // Incorporate counter into state (CTR mode requirement)
    const counterBytes = new Uint8Array(8);
    const counterView = new DataView(counterBytes.buffer);
    counterView.setBigUint64(0, BigInt(startBlockIndex + i), false);
    
    const counterHash = shake256Hash(
      concatBytes(counterBytes, stringToBytes('CTR')),
      BYTES.REGISTER
    );
    const counterInt = bytesToBigInt(counterHash);
    state.registers[0] ^= counterInt;
    
    // Try WASM first, fallback to JavaScript
    let result: Uint8Array | null = null;
    
    if (encrypt) {
      result = encryptBlockWASM(blocks[i], key, iv, BigInt(startBlockIndex + i), state, keyMaterial);
      if (!result) {
        result = encryptBlock(blocks[i], key, iv, BigInt(startBlockIndex + i), state, keyMaterial);
      }
    } else {
      result = decryptBlockWASM(blocks[i], key, iv, BigInt(startBlockIndex + i), state, keyMaterial);
      if (!result) {
        result = decryptBlock(blocks[i], key, iv, BigInt(startBlockIndex + i), state, keyMaterial);
      }
    }
    
    results[i] = result;
  }
  
  return results;
}

/**
 * Fast CTR Mode Encryption with chunked parallel processing
 * 
 * Each block can be encrypted independently (parallelizable)
 * Output format: nonce (16 bytes) || ciphertext
 * 
 * @param plaintext - Data to encrypt
 * @param key - Encryption key
 * @param nonce - Optional 16-byte nonce (auto-generated if not provided)
 * @param onProgress - Optional progress callback (0-100)
 */
export async function encryptCTRFast(
  plaintext: Uint8Array,
  key: Uint8Array,
  nonce?: Uint8Array,
  onProgress?: (progress: number) => void
): Promise<Uint8Array> {
  // WASM is 7x faster than pure JavaScript despite overhead
  const startTime = performance.now();
  await initWASM();
  
  // Generate nonce if not provided
  const actualNonce = nonce || randomBytes(BYTES.NONCE);
  if (actualNonce.length !== BYTES.NONCE) {
    throw new Error(`Nonce must be ${BYTES.NONCE} bytes`);
  }
  
  // Derive IV from nonce
  const iv = shake256Hash(
    concatBytes(actualNonce, stringToBytes(DOMAIN.CTR_IV)),
    BYTES.IV
  );
  
  // Key expansion (done once)
  const keyMaterial = expandKey(key);
  
  // Pad plaintext
  const padded = pkcs7Pad(plaintext, BYTES.BLOCK);
  const numBlocks = padded.length / BYTES.BLOCK;
  
  // Allocate output: nonce + ciphertext
  const output = new Uint8Array(BYTES.NONCE + padded.length);
  output.set(actualNonce, 0);
  
  // Adaptive chunk size based on file size
  const chunkSizeBlocks = getChunkSize(padded.length);
  const yieldInterval = getYieldInterval(padded.length);
  
  // Process in chunks for better performance and progress reporting
  const numChunks = Math.ceil(numBlocks / chunkSizeBlocks);
  
  for (let chunkIdx = 0; chunkIdx < numChunks; chunkIdx++) {
    const startBlock = chunkIdx * chunkSizeBlocks;
    const endBlock = Math.min(startBlock + chunkSizeBlocks, numBlocks);
    const actualChunkSize = endBlock - startBlock;
    
    // Extract blocks for this chunk (reuse array when possible)
    const blocks: Uint8Array[] = new Array(actualChunkSize);
    for (let n = 0; n < actualChunkSize; n++) {
      blocks[n] = padded.subarray((startBlock + n) * BYTES.BLOCK, (startBlock + n + 1) * BYTES.BLOCK);
    }
    
    // Process chunk synchronously (much faster)
    const results = processChunk(blocks, startBlock, key, iv, keyMaterial, true);
    
    // Copy results to output (batch copy for better performance)
    const outputOffset = BYTES.NONCE + startBlock * BYTES.BLOCK;
    for (let i = 0; i < results.length; i++) {
      output.set(results[i], outputOffset + i * BYTES.BLOCK);
    }
    
    // Report progress (less frequently for better performance)
    if (onProgress && (chunkIdx % Math.max(1, Math.floor(numChunks / 100)) === 0 || chunkIdx === numChunks - 1)) {
      const progress = Math.floor(((chunkIdx + 1) / numChunks) * 100);
      onProgress(progress);
    }
    
    // Yield to event loop less frequently for medium/large files
    if (chunkIdx < numChunks - 1 && chunkIdx % yieldInterval === 0) {
      await yieldToMain();
    }
  }
  
  const endTime = performance.now();
  const totalTime = ((endTime - startTime) / 1000).toFixed(2);
  const mbSize = (plaintext.length / (1024 * 1024)).toFixed(2);
  const mbPerSec = (plaintext.length / (1024 * 1024) / ((endTime - startTime) / 1000)).toFixed(2);
  console.log(`⚡ Encrypted ${mbSize}MB in ${totalTime}s (${mbPerSec} MB/s)`);
  
  return output;
}

/**
 * Fast CTR Mode Decryption with chunked parallel processing
 * 
 * Input format: nonce (16 bytes) || ciphertext
 * 
 * @param ciphertext - Data to decrypt
 * @param key - Decryption key
 * @param onProgress - Optional progress callback (0-100)
 */
export async function decryptCTRFast(
  ciphertext: Uint8Array,
  key: Uint8Array,
  onProgress?: (progress: number) => void
): Promise<Uint8Array> {
  // WASM is 7x faster than pure JavaScript
  await initWASM();
  
  if (ciphertext.length < BYTES.NONCE + BYTES.BLOCK) {
    throw new Error('Ciphertext too short');
  }
  
  // Extract nonce
  const nonce = ciphertext.subarray(0, BYTES.NONCE);
  const encryptedData = ciphertext.subarray(BYTES.NONCE);
  
  if (encryptedData.length % BYTES.BLOCK !== 0) {
    throw new Error('Invalid ciphertext length');
  }
  
  // Derive IV from nonce
  const iv = shake256Hash(
    concatBytes(nonce, stringToBytes(DOMAIN.CTR_IV)),
    BYTES.IV
  );
  
  // Key expansion (done once)
  const keyMaterial = expandKey(key);
  
  const numBlocks = encryptedData.length / BYTES.BLOCK;
  const padded = new Uint8Array(encryptedData.length);
  
  // Adaptive chunk size based on file size
  const chunkSizeBlocks = getChunkSize(encryptedData.length);
  const yieldInterval = getYieldInterval(encryptedData.length);
  
  // Process in chunks
  const numChunks = Math.ceil(numBlocks / chunkSizeBlocks);
  
  for (let chunkIdx = 0; chunkIdx < numChunks; chunkIdx++) {
    const startBlock = chunkIdx * chunkSizeBlocks;
    const endBlock = Math.min(startBlock + chunkSizeBlocks, numBlocks);
    const actualChunkSize = endBlock - startBlock;
    
    // Extract blocks for this chunk (pre-allocated array)
    const blocks: Uint8Array[] = new Array(actualChunkSize);
    for (let n = 0; n < actualChunkSize; n++) {
      blocks[n] = encryptedData.subarray((startBlock + n) * BYTES.BLOCK, (startBlock + n + 1) * BYTES.BLOCK);
    }
    
    // Process chunk synchronously (much faster)
    const results = processChunk(blocks, startBlock, key, iv, keyMaterial, false);
    
    // Copy results to output (batch copy)
    const outputOffset = startBlock * BYTES.BLOCK;
    for (let i = 0; i < results.length; i++) {
      padded.set(results[i], outputOffset + i * BYTES.BLOCK);
    }
    
    // Report progress (less frequently)
    if (onProgress && (chunkIdx % Math.max(1, Math.floor(numChunks / 100)) === 0 || chunkIdx === numChunks - 1)) {
      const progress = Math.floor(((chunkIdx + 1) / numChunks) * 100);
      onProgress(progress);
    }
    
    // Yield to event loop less frequently for medium/large files
    if (chunkIdx < numChunks - 1 && chunkIdx % yieldInterval === 0) {
      await yieldToMain();
    }
  }
  
  // Remove padding
  return pkcs7Unpad(padded);
}

/**
 * Fast encryption with auto-generated nonce (convenience function)
 */
export async function encryptFast(
  plaintext: Uint8Array,
  key: Uint8Array,
  onProgress?: (progress: number) => void
): Promise<Uint8Array> {
  return encryptCTRFast(plaintext, key, undefined, onProgress);
}

/**
 * Fast decryption (convenience function)
 */
export async function decryptFast(
  ciphertext: Uint8Array,
  key: Uint8Array,
  onProgress?: (progress: number) => void
): Promise<Uint8Array> {
  return decryptCTRFast(ciphertext, key, onProgress);
}

