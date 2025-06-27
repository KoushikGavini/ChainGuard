# Contributing to ChainGuard

Thank you for your interest in contributing to ChainGuard! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:
- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on constructive criticism
- Respect differing viewpoints and experiences

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- A clear and descriptive title
- Steps to reproduce the issue
- Expected behavior vs actual behavior
- Your environment (OS, Rust version, etc.)
- Any relevant error messages or logs

### Suggesting Enhancements

Enhancement suggestions are welcome! Please include:

- A clear and descriptive title
- Detailed description of the proposed feature
- Use cases and benefits
- Possible implementation approach (if you have ideas)

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`cargo test`)
6. Run clippy (`cargo clippy -- -D warnings`)
7. Format your code (`cargo fmt`)
8. Commit your changes with a descriptive message
9. Push to your fork
10. Open a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/ChainGuard.git
cd ChainGuard

# Install Z3 (see README for platform-specific instructions)

# Build the project
cargo build

# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run -- analyze test_chaincode.go
```

## Project Structure

```
src/
├── analyzer/         # Core analysis modules
├── solana/          # Solana-specific analyzers
├── fabric/          # Fabric-specific analyzers
├── token_standards/ # Token standard validators
├── reporter/        # Report generation
├── validator/       # AI validation
└── main.rs          # CLI entry point
```

## Adding New Security Checks

To add a new security check:

1. Create a new module in the appropriate analyzer directory
2. Implement the analysis logic
3. Add tests for your checker
4. Update the main analyzer to include your check
5. Document the new check in the README

Example structure for a new Solana check:
```rust
// src/solana/new_check.rs
use crate::{Finding, Result, Severity};
use regex::Regex;

pub struct NewChecker;

impl NewChecker {
    pub fn new() -> Self {
        Self
    }
    
    pub fn analyze(&self, content: &str) -> Result<Vec<Finding>> {
        // Your analysis logic here
        Ok(vec![])
    }
}
```

## Testing

- Unit tests: `cargo test`
- Integration tests: `cargo test --test '*'`
- Specific test: `cargo test test_name`
- With output: `cargo test -- --nocapture`

## Documentation

- Update README.md for user-facing changes
- Add inline documentation for public APIs
- Include examples in doc comments
- Update CHANGELOG.md following Keep a Changelog format

## Commit Messages

Follow conventional commits:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `style:` Code style changes (formatting, etc.)
- `refactor:` Code refactoring
- `test:` Test additions or modifications
- `chore:` Maintenance tasks
- `perf:` Performance improvements

## Release Process

1. Update version in Cargo.toml
2. Update CHANGELOG.md
3. Create a PR with version bump
4. After merge, tag the release: `git tag v0.1.0`
5. Push tag: `git push origin v0.1.0`
6. GitHub Actions will handle the rest

## Questions?

Feel free to open an issue for questions or join our discussions! 