/**
 * Optimized BigInt operations using typed arrays where possible
 * 
 * These functions provide faster alternatives to pure BigInt operations
 * by using Uint8Array operations and only converting when necessary.
 */

/**
 * Fast XOR of two 512-bit values represented as Uint8Array[64]
 * Much faster than BigInt XOR for 512-bit values
 */
export function xor512Fast(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

/**
 * Fast rotate left for 512-bit value (Uint8Array[64])
 * Rotates by n bits
 */
export function rotateLeft512Fast(data: Uint8Array, n: number): Uint8Array {
  const result = new Uint8Array(64);
  const byteShift = Math.floor(n / 8);
  const bitShift = n % 8;
  
  for (let i = 0; i < 64; i++) {
    const srcIdx = (i + byteShift) % 64;
    const nextIdx = (i + byteShift + 1) % 64;
    
    const low = (data[srcIdx] << bitShift) & 0xFF;
    const high = bitShift > 0 ? (data[nextIdx] >> (8 - bitShift)) : 0;
    
    result[i] = low | high;
  }
  
  return result;
}

/**
 * Convert BigInt (512-bit) to Uint8Array[64]
 */
export function bigIntToBytes512(value: bigint): Uint8Array {
  const result = new Uint8Array(64);
  let temp = value;
  for (let i = 0; i < 64; i++) {
    result[i] = Number(temp & 0xFFn);
    temp = temp >> 8n;
  }
  return result;
}

/**
 * Convert Uint8Array[64] to BigInt (512-bit)
 */
export function bytes512ToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 63; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/**
 * Fast left shift for 512-bit value
 * Returns new Uint8Array, doesn't modify original
 */
export function shiftLeft512Fast(data: Uint8Array, n: number): Uint8Array {
  if (n === 0) return new Uint8Array(data);
  if (n >= 512) return new Uint8Array(64); // All zeros
  
  const result = new Uint8Array(64);
  const byteShift = Math.floor(n / 8);
  const bitShift = n % 8;
  
  for (let i = byteShift; i < 64; i++) {
    const srcIdx = i - byteShift;
    const nextIdx = srcIdx - 1;
    
    const low = bitShift > 0 && nextIdx >= 0 
      ? (data[nextIdx] >> (8 - bitShift))
      : 0;
    const high = (data[srcIdx] << bitShift) & 0xFF;
    
    result[i] = low | high;
  }
  
  return result;
}

