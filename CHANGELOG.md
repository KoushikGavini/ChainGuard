# Changelog

All notable changes to ShieldContract will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2025-07-08

### Changed
- **BREAKING**: Renamed project from "chainguard" to "shieldcontract"
- Updated binary name from `chainguard` to `shieldcontract`
- Updated package name and all references throughout codebase
- Updated configuration directory from `.chainguard` to `.shieldcontract`
- Updated default configuration file from `chainguard.toml` to `shieldcontract.toml`
- Updated Docker image and container references
- Updated all documentation and examples
- Improved README accuracy by removing false promises and stub command documentation
- Fixed CI badge URL to match actual workflow
- Updated command documentation to reflect actual functionality

### Fixed
- Fixed CI pipeline formatting issues
- Corrected repository URLs and references
- Fixed command examples in documentation
- Resolved rustfmt and clippy issues

### Documentation
- Made README more accurate about current capabilities vs future plans
- Removed timeline references and "coming soon" statements
- Updated Available Commands table to show only fully functional commands
- Added transparency note about commands with limited functionality
- Updated examples to use correct command syntax

## [0.1.0] - 2024-12-27

### Added
- Initial release of ShieldContract
- Comprehensive Hyperledger Fabric chaincode analysis
- Solana smart contract security analysis with 15+ vulnerability detectors
- Multi-LLM consensus validation for AI-generated code
- Performance benchmarking and optimization suggestions
- Compliance auditing with multiple framework support
- Foundation for future ERC token standard support (ERC-20, ERC-721, ERC-1155, ERC-777)
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
- General blockchain security analysis

[Unreleased]: https://github.com/KoushikGavini/ShieldContract/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/KoushikGavini/ShieldContract/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/KoushikGavini/ShieldContract/releases/tag/v0.1.0 