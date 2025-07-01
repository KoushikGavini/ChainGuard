# Changelog

All notable changes to ChainGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2024-12-27

### Added
- Initial release of ChainGuard
- Comprehensive Hyperledger Fabric chaincode analysis
- Solana smart contract security analysis with 15+ vulnerability detectors
- Multi-LLM consensus validation for AI-generated code
- Performance benchmarking and optimization suggestions
- Compliance auditing with multiple framework support
- Support for ERC-20, ERC-721, ERC-1155, and ERC-777 token standards
- Stablecoin-specific security checks
- Multiple output formats: JSON, HTML, PDF, CSV, SARIF, Markdown
- Interactive mode for real-time validation
- Formal verification capabilities using Z3
- Cross-platform support (macOS, Linux)

### Security Checks
- Account validation and ownership verification
- Signer verification for sensitive operations
- Arithmetic overflow/underflow detection
- Cross-Program Invocation (CPI) security
- Program Derived Address (PDA) vulnerability detection
- Type confusion and discriminator validation
- Duplicate mutable account detection
- Rent exemption calculation verification
- Deprecated sysvar usage warnings
- Performance optimization recommendations

### Platform Support
- Hyperledger Fabric chaincode (Go, JavaScript, TypeScript)
- Solana programs (Rust)
- Ethereum smart contracts (Solidity)
- General blockchain security analysis

[Unreleased]: https://github.com/KoushikGavini/ChainGuard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/KoushikGavini/ChainGuard/releases/tag/v0.1.0 