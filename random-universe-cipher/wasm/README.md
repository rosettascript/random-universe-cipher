# Random Universe Cipher - WebAssembly Module

High-performance WebAssembly implementation of the Random Universe Cipher block encryption.

## Building

```bash
# Install Rust and wasm-pack first (see WASM_SETUP.md)

# Build WASM module
wasm-pack build --target web --release

# Output will be in pkg/ directory
```

## Status

🚧 **Work in Progress**

The current implementation provides the foundation but needs:
1. Complete block encryption matching TypeScript exactly
2. SHAKE256 implementation (or use existing WASM library)
3. Full integration with JavaScript codebase

## Performance Goals

- 5-20x faster than JavaScript for block encryption
- Support for parallel processing
- Minimal memory overhead

## Architecture

- **Rust core**: Block encryption, GF arithmetic, register operations
- **WASM bindings**: Expose functions to JavaScript
- **JS wrapper**: Integration with existing codebase

