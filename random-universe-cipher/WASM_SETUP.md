# WebAssembly Performance Optimization Guide

## Why WebAssembly?

The current JavaScript implementation has performance bottlenecks:
1. **BigInt operations** - Very slow in JS (10-100x slower than native)
2. **SHAKE256 hashing** - Called thousands of times per file
3. **GF(2^8) arithmetic** - Table lookups are fast, but BigInt conversions are slow
4. **No true parallelism** - JavaScript is single-threaded

WebAssembly can provide **5-20x speedup** for cryptographic operations.

## Setup Instructions

### 1. Install Rust and wasm-pack

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install wasm-pack
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
```

### 2. Build WASM Module

```bash
cd wasm
wasm-pack build --target web --release
cd ..
```

### 3. Update package.json

Add build script:
```json
"scripts": {
  "build:wasm": "cd wasm && wasm-pack build --target web --release",
  "build": "npm run build:wasm && tsc && vite build"
}
```

## Performance Expectations

- **15MB file encryption**: ~2-5 seconds (vs 20-30s in JS)
- **100MB file encryption**: ~15-30 seconds (vs 2-3 minutes in JS)
- **Memory usage**: Similar or better

## Implementation Status

The WASM implementation is a work in progress. The current Rust code provides the foundation, but needs:
1. Full SHAKE256 implementation (or use existing WASM library)
2. Complete block encryption matching TypeScript exactly
3. JS bindings and integration

## Alternative: Immediate Optimizations

While WASM is being developed, we can:
1. ✅ Use larger chunk sizes (already done)
2. ✅ Reduce yields (already done)
3. 🔄 Use Web Workers with SharedArrayBuffer for true parallelism
4. 🔄 Optimize BigInt operations with typed arrays
5. 🔄 Cache SHAKE256 results where possible

