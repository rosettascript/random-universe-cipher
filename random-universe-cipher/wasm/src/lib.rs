//! Random Universe Cipher - WebAssembly Implementation
//! 
//! High-performance WASM implementation of the block encryption core
//! Processes blocks in batches for maximum performance

use wasm_bindgen::prelude::*;
use sha3::{Sha3_256, Digest};

// Constants matching the TypeScript implementation
const BLOCK_SIZE: usize = 32;
const ROUNDS: usize = 24;
const REGISTER_COUNT: usize = 7;
const REGISTER_SIZE: usize = 64; // 512 bits = 64 bytes
const ACCUMULATOR_SIZE: usize = 128; // 1024 bits

// GF(2^8) multiplication (AES polynomial: 0x1B)
fn gf_mul(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut a = a;
    let mut b = b;
    
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let hi_bit_set = a & 0x80 != 0;
        a <<= 1;
        if hi_bit_set {
            a ^= 0x1B; // AES polynomial
        }
        b >>= 1;
    }
    result
}

// Fast GF multiplication for a 64-byte register
fn gf_mul_register(reg: &[u8; REGISTER_SIZE], multiplier: u8) -> [u8; REGISTER_SIZE] {
    let mut result = [0u8; REGISTER_SIZE];
    for i in 0..REGISTER_SIZE {
        result[i] = gf_mul(reg[i], multiplier);
    }
    result
}

// Rotate 512-bit register left by n bits
fn rotate_left_512(reg: &[u8; REGISTER_SIZE], n: usize) -> [u8; REGISTER_SIZE] {
    let mut result = [0u8; REGISTER_SIZE];
    let byte_shift = n / 8;
    let bit_shift = n % 8;
    
    for i in 0..REGISTER_SIZE {
        let src_idx = (i + byte_shift) % REGISTER_SIZE;
        let next_idx = (i + byte_shift + 1) % REGISTER_SIZE;
        
        let low = (reg[src_idx] << bit_shift) & 0xFF;
        let high = if bit_shift > 0 {
            reg[next_idx] >> (8 - bit_shift)
        } else {
            0
        };
        
        result[i] = low | high;
    }
    result
}

// XOR two 512-bit registers
fn xor_512(a: &[u8; REGISTER_SIZE], b: &[u8; REGISTER_SIZE]) -> [u8; REGISTER_SIZE] {
    let mut result = [0u8; REGISTER_SIZE];
    for i in 0..REGISTER_SIZE {
        result[i] = a[i] ^ b[i];
    }
    result
}

// Convert u8 array to u64 (little-endian, first 8 bytes)
fn bytes_to_u64(bytes: &[u8; REGISTER_SIZE]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

// Convert u64 to u8 array (little-endian, first 8 bytes)
fn u64_to_bytes(value: u64, output: &mut [u8; REGISTER_SIZE]) {
    let bytes = value.to_le_bytes();
    for i in 0..8 {
        output[i] = bytes[i];
    }
}

#[wasm_bindgen]
pub struct CipherState {
    registers: [[u8; REGISTER_SIZE]; REGISTER_COUNT],
    accumulator: [u8; ACCUMULATOR_SIZE],
    accumulator_sum: u64, // Track sum of results for accumulator (simplified)
}

#[wasm_bindgen]
impl CipherState {
    #[wasm_bindgen(constructor)]
    pub fn new(key_material_registers: &[u8]) -> CipherState {
        let mut registers = [[0u8; REGISTER_SIZE]; REGISTER_COUNT];
        for i in 0..REGISTER_COUNT {
            let offset = i * REGISTER_SIZE;
            if offset + REGISTER_SIZE <= key_material_registers.len() {
                registers[i].copy_from_slice(&key_material_registers[offset..offset + REGISTER_SIZE]);
            }
        }
        CipherState {
            registers,
            accumulator: [0u8; ACCUMULATOR_SIZE],
            accumulator_sum: 0,
        }
    }
    
    #[wasm_bindgen(getter)]
    pub fn get_registers(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(REGISTER_COUNT * REGISTER_SIZE);
        for reg in &self.registers {
            result.extend_from_slice(reg);
        }
        result
    }
    
    #[wasm_bindgen(getter)]
    pub fn get_accumulator_sum(&self) -> u64 {
        self.accumulator_sum
    }
}

/// Execute a single round of encryption (optimized WASM version)
/// This is the HOT PATH - called 24 times per block
#[wasm_bindgen]
pub fn execute_round_wasm(
    state: &mut CipherState,
    round_index: usize,
    selectors: &[u16],
    sbox: &[u8],
    round_key_bytes: &[u8],
    key_constants: &[u8], // Pre-computed key constants for each selector
) {
    if round_key_bytes.len() < REGISTER_SIZE || sbox.len() < 256 {
        return;
    }
    
    let round_key: [u8; REGISTER_SIZE] = {
        let mut arr = [0u8; REGISTER_SIZE];
        arr.copy_from_slice(&round_key_bytes[..REGISTER_SIZE]);
        arr
    };
    
    // Process each selector
    for (sel_idx, &sel) in selectors.iter().enumerate() {
        // Select destination register: (R[0] XOR selector XOR roundKey) mod 7
        let r0_u64 = bytes_to_u64(&state.registers[0]);
        let round_key_u64 = bytes_to_u64(&round_key);
        let dest_val = (r0_u64 ^ u64::from(sel) ^ round_key_u64) & 0xFFFFFFFF;
        let place_idx = (dest_val % 7) as usize;
        
        // Compute non-linear transformation
        let temp = (sel * 2) & 0xFFFF;
        let state_byte = state.registers[place_idx][0]; // Top byte
        
        // GF multiplication
        let mut gf_result = gf_mul((temp & 0xFF) as u8, state_byte);
        
        // XOR with pre-computed key constant
        if sel_idx < key_constants.len() {
            gf_result ^= key_constants[sel_idx];
        }
        
        // Apply S-box
        let result = sbox[gf_result as usize];
        
        // Update state register: GF multiply each byte
        state.registers[place_idx] = gf_mul_register(&state.registers[place_idx], result);
        
        // XOR with shifted result
        let shift_amount = (sel % 16) as usize;
        let mut shifted_bytes = [0u8; REGISTER_SIZE];
        if shift_amount < 8 {
            shifted_bytes[0] = result << shift_amount;
        }
        state.registers[place_idx] = xor_512(&state.registers[place_idx], &shifted_bytes);
        
        // Apply S-box to low byte
        let low_byte = state.registers[place_idx][REGISTER_SIZE - 1];
        let sbox_result = sbox[low_byte as usize];
        let mut sbox_bytes = [0u8; REGISTER_SIZE];
        sbox_bytes[REGISTER_SIZE - 1] = sbox_result;
        state.registers[place_idx] = xor_512(&state.registers[place_idx], &sbox_bytes);
        
        // Rotate left by 1
        state.registers[place_idx] = rotate_left_512(&state.registers[place_idx], 1);
        
        // Mix with adjacent register
        state.registers[place_idx] = xor_512(
            &state.registers[place_idx],
            &state.registers[(place_idx + 1) % REGISTER_COUNT],
        );
        
        // Accumulate result (simplified - track sum)
        state.accumulator_sum = state.accumulator_sum.wrapping_add(u64::from(result));
    }
    
    // Inter-round state mixing
    for i in 0..REGISTER_COUNT {
        state.registers[i] = xor_512(
            &state.registers[i],
            &state.registers[(i + 1) % REGISTER_COUNT],
        );
        state.registers[i] = xor_512(
            &state.registers[i],
            &state.registers[(i + 2) % REGISTER_COUNT],
        );
    }
}

/// Process multiple blocks in batch (reduces JS/WASM boundary crossings)
/// This is the main performance optimization
#[wasm_bindgen]
pub fn encrypt_blocks_batch(
    plaintext_blocks: &[u8],
    key_material_registers: &[u8],
    selectors: &[u16],
    sboxes: &[u8], // Flattened: 24 rounds × 256 bytes
    round_keys: &[u8], // Flattened: 24 rounds × 64 bytes
    key_constants_batch: &[u8], // Pre-computed constants for all selectors
    num_blocks: usize,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(num_blocks * BLOCK_SIZE);
    
    // Process each block
    for block_idx in 0..num_blocks {
        let block_offset = block_idx * BLOCK_SIZE;
        if block_offset + BLOCK_SIZE > plaintext_blocks.len() {
            break;
        }
        
        // Create state for this block
        let mut state = CipherState::new(key_material_registers);
        
        // Reset accumulator
        state.accumulator.fill(0);
        
        // Execute all 24 rounds
        for round in 0..ROUNDS {
            let sbox_offset = round * 256;
            let round_key_offset = round * REGISTER_SIZE;
            let key_const_offset = block_idx * selectors.len();
            
            if sbox_offset + 256 <= sboxes.len() 
                && round_key_offset + REGISTER_SIZE <= round_keys.len()
                && key_const_offset + selectors.len() <= key_constants_batch.len() {
                
                let sbox = &sboxes[sbox_offset..sbox_offset + 256];
                let round_key = &round_keys[round_key_offset..round_key_offset + REGISTER_SIZE];
                let key_consts = &key_constants_batch[key_const_offset..key_const_offset + selectors.len()];
                
                execute_round_wasm(
                    &mut state,
                    round,
                    selectors,
                    sbox,
                    round_key,
                    key_consts,
                );
            }
        }
        
        // Generate keystream (simplified - would need SHAKE256)
        // For now, use a simple hash
        let mut hasher = Sha3_256::new();
        hasher.update(&state.accumulator);
        for reg in &state.registers {
            hasher.update(reg);
        }
        let keystream = hasher.finalize();
        
        // XOR plaintext with keystream
        let plaintext_block = &plaintext_blocks[block_offset..block_offset + BLOCK_SIZE];
        for i in 0..BLOCK_SIZE.min(plaintext_block.len()) {
            output.push(plaintext_block[i] ^ keystream[i]);
        }
    }
    
    output
}
