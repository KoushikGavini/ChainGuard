# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

### Essential Commands
```bash
# Build development version
cargo build

# Build optimized release version
cargo build --release

# Run all tests
cargo test

# Run tests with output visible
cargo test -- --nocapture

# Format code
cargo fmt

# Lint code (must pass in CI)
cargo clippy -- -D warnings

# Security audit
cargo audit

# Run the tool
cargo run -- --version
cargo run -- analyze test_chaincode.go --fabric
```

### Pre-push Checklist
Always run these commands before pushing code:
1. `cargo fmt` - Format code
2. `cargo clippy -- -D warnings` - Fix all linting issues
3. `cargo test` - Ensure all tests pass
4. `cargo build --release` - Verify release build works

## Architecture Overview

ChainGuard is a security analysis CLI tool for blockchain smart contracts, built in Rust with a modular, trait-based architecture supporting 8+ blockchain platforms.

### Core Architecture Flow
```
main.rs (CLI entry)
  → Command parsing (clap)
  → Platform-specific analyzer selection
  → Parallel analysis engine (rayon)
  → Finding aggregation
  → Report generation
```

### Key Design Patterns

1. **Analyzer Trait System**: All platform analyzers implement the common `Analyzer` trait defined in `src/analyzer/mod.rs`. When adding new platforms, implement this trait.

2. **Platform Modules**: Each blockchain has its own module:
   - `src/fabric/` - Hyperledger Fabric analysis
   - `src/solana/` - Solana program analysis
   - `src/cosmos/` - Cosmos/CosmWasm support
   - `src/token_standards/` - Token compliance (ERC20, ERC721, stablecoin)

3. **Finding Codes**: Follow the pattern `PLATFORM-CATEGORY-NUMBER`:
   - `SOL-ACC-001` - Solana account validation issue
   - `FABRIC-SEC-ND-001` - Fabric security nondeterminism issue
   - `STABLE-ORACLE-001` - Stablecoin oracle vulnerability

4. **Parallel Processing**: Uses Rayon for concurrent file analysis. Be mindful of shared state when modifying analyzers.

5. **AI Integration**: The `src/llm/` module provides multi-LLM consensus analysis. API keys are stored in `~/.chainguard/auth.toml`.

### Adding New Features

When implementing new analysis rules:
1. Add the rule to the appropriate platform module
2. Use existing severity levels: Critical, High, Medium, Low, Info
3. Include clear error messages with remediation suggestions
4. Add tests in the corresponding test file
5. Update the finding codes documentation if adding new categories

### Dependencies and Requirements

- **Rust 1.82+**: Required for building the project due to dependency requirements
- **Z3 Solver**: Required for formal verification. Must be installed separately.
- **Tree-sitter**: Used for parsing multiple languages (Go, Rust, JS, TS)
- **WebAssembly**: Wasmtime/Wasmer for sandboxed execution
- **Async Runtime**: Tokio with full features

### Testing Approach

- Unit tests: Located alongside source files
- Integration tests: In `tests/` directory
- Example vulnerable contracts: In `examples/` directory
- Run specific test: `cargo test test_name`
- Run with logging: `RUST_LOG=debug cargo test`

### Performance Considerations

- File analysis is parallelized by default
- Large codebases benefit from incremental analysis
- Cache analysis results when possible
- Avoid blocking operations in analyzers

### Security Notes

- Never log or expose API keys
- Validate all file paths before access
- Use sandboxed execution for untrusted code
- Follow Rust's memory safety guarantees