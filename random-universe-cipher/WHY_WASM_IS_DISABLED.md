# Why WASM Is Currently Disabled

## The Problem

WASM is **making things slower**, not faster, due to overhead.

### Current Architecture Issue

For a 1.38MB file (45,000 blocks):
- **1,080,000 JS→WASM calls** (24 rounds × 45,000 blocks)
- Each call has ~1-10μs overhead
- Total overhead: 1-10 seconds just in call overhead
- Plus data conversion overhead (BigInt ↔ bytes)
- Plus object creation/destruction overhead

**Result**: 0.01 MB/s with WASM (worse than JavaScript!)

### Why It's Slow

```javascript
// Current (BAD - too many calls)
for each block (45,000):
  for each round (24):
    JS → WASM call      // ← 1,080,000 calls!
    convert data
    execute round
    convert back
    JS ← WASM return
```

### What We Need Instead

```javascript
// Ideal (GOOD - batch processing)
for each batch of 100 blocks:
  JS → WASM call         // ← Only ~450 calls!
  process 100 blocks × 24 rounds in WASM
  JS ← WASM return
```

## Current Performance

**Pure JavaScript** (WASM disabled):
- 1MB: ~20-40 seconds
- Expected: 1.38MB in ~25-55 seconds

**With current WASM** (too much overhead):
- 1.38MB: 105 seconds (slower!)

## To Make WASM Fast

Would need to:
1. **Batch multiple blocks** into single WASM call
2. **Complete the `encrypt_blocks_batch` function** in Rust
3. **Process 100+ blocks at once** in WASM
4. **Minimize JS↔WASM boundary crossings**

This is complex and would require significant WASM code rewrite.

## Conclusion

**Pure JavaScript is currently faster** because:
- No JS↔WASM overhead
- No data conversion overhead  
- Simpler code path

WASM would only be faster if we batch process many blocks in a single call, which requires completing the batch implementation in Rust.

## What To Do Now

1. **Use pure JavaScript** - It's the fastest we have
2. **Accept the speed** - ~20-40s per MB is expected for this heavy cipher
3. **Or simplify the cipher** - Reduce rounds/register size for speed
4. **Or use established ciphers** - AES is 100x faster

The cipher design (512-bit registers, 24 rounds, complex operations) is inherently slow in any language. JavaScript with optimizations is the best we can do without major redesign.

