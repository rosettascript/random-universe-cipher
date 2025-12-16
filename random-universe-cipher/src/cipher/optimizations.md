# Performance Optimization Strategies

## Current Bottlenecks (in order of impact)

1. **BigInt Operations** (70% of time)
   - BigInt arithmetic is 10-100x slower than native integers
   - Used extensively in register operations
   - Solution: WebAssembly with native 64-bit integers

2. **SHAKE256 Hashing** (20% of time)
   - Called once per selector per round = thousands of times
   - Each call processes small amounts of data
   - Solution: WASM SHAKE256 or native crypto API

3. **GF(2^8) Arithmetic** (5% of time)
   - Table lookups are fast, but BigInt conversions slow
   - Solution: Use u8 directly in WASM

4. **Memory Allocations** (5% of time)
   - Creating new arrays for each block
   - Solution: Pre-allocate and reuse buffers

## Immediate Optimizations (No WASM)

### 1. Use Typed Arrays Instead of BigInt Where Possible
```typescript
// Instead of: BigInt operations on 512-bit registers
// Use: Uint8Array[64] with manual bit operations
```

### 2. Cache SHAKE256 Results
```typescript
// Cache selector ordering results for same (key, iv, blockNumber)
const selectorCache = new Map<string, number[]>();
```

### 3. Batch Operations
```typescript
// Process multiple blocks in a single WASM call
// Reduce JS/WASM boundary crossings
```

### 4. Use SharedArrayBuffer for Parallel Processing
```typescript
// True parallelism with Web Workers
// Each worker processes a chunk independently
```

## WebAssembly Implementation Plan

### Phase 1: Core Block Encryption (Critical Path)
- [x] Rust project setup
- [ ] Full block encryption in Rust
- [ ] WASM bindings
- [ ] JS integration

### Phase 2: SHAKE256 in WASM
- [ ] Use existing WASM SHAKE256 library
- [ ] Or implement optimized version

### Phase 3: Full Pipeline
- [ ] Key expansion in WASM
- [ ] Complete CTR mode in WASM
- [ ] Parallel processing with workers

## Expected Performance Gains

| File Size | Current (JS) | With WASM | Speedup |
|-----------|--------------|-----------|---------|
| 1 MB      | 2-3s         | 0.3-0.5s  | 6x      |
| 15 MB     | 20-30s       | 2-4s      | 7-10x   |
| 100 MB    | 2-3 min      | 15-25s    | 5-8x    |
| 1 GB      | 20-30 min    | 2-4 min   | 7-10x   |

## Alternative: Use Native Crypto APIs

For SHAKE256, we could use:
- Web Crypto API (if available)
- SubtleCrypto (limited support)
- Native browser implementations

But these may not be available for SHAKE256 specifically.

