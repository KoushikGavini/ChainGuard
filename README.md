# ShieldContract

> Security analysis tool for blockchain smart contracts with focus on Hyperledger Fabric and Solana

ShieldContract is a security analysis tool designed for blockchain developers working with Hyperledger Fabric and Solana platforms. It provides vulnerability detection, code review capabilities, and basic performance analysis for smart contracts.

[![CI](https://github.com/KoushikGavini/ChainGuard/workflows/CI/badge.svg)](https://github.com/KoushikGavini/ChainGuard/actions/workflows/rust.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=flat&logo=rust&logoColor=white)](https://www.rust-lang.org/)

## Features

### Supported Platforms
- **Hyperledger Fabric**: Chaincode analysis with determinism checking, basic endorsement policy validation, and private data leak detection
- **Solana**: Rust program analysis with account validation, arithmetic safety checks, and CPI security validation

### Analysis Capabilities
- **Security Vulnerability Detection**: Platform-specific security issue identification
- **Performance Analysis**: Basic performance issue detection and optimization suggestions
- **Code Quality Checks**: Best practices validation for supported platforms

## Installation

### Prerequisites
- Rust 1.82+ (install via [rustup.rs](https://rustup.rs/))

### Build from Source
```bash
# Clone the repository
git clone https://github.com/KoushikGavini/ShieldContract.git
cd ShieldContract

# Build and install
cargo install --path .

# Or build without installing
cargo build --release
./target/release/shieldcontract --version
```

## Getting Started

### Basic Analysis

```bash
# Analyze Fabric chaincode
./target/release/shieldcontract analyze examples/test_chaincode.go --fabric

# Analyze Solana program  
./target/release/shieldcontract analyze examples/vulnerable_solana_program.rs.example --solana
```

### Expected Output

For Fabric chaincode:
```text
ShieldContract Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Analysis Report
==========================
Total Findings: 3
Critical: 0 | High: 2 | Medium: 1 | Low: 0 | Info: 0

[High] FABRIC-ND-001 - Nondeterministic operation detected
  File: test_chaincode.go:15
  Use of time.Now() can lead to nondeterministic behavior

[High] FABRIC-EP-001 - Missing endorsement policy validation
  File: test_chaincode.go:1
  Chaincode does not validate transaction creator or MSP ID

[Medium] FABRIC-MVCC-001 - Potential MVCC read conflict
  File: test_chaincode.go:1
  Multiple state reads detected
```

For Solana programs:
```text
ShieldContract Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Analysis Report
==========================
Total Findings: 8
Critical: 2 | High: 4 | Medium: 2 | Low: 0 | Info: 0

[Critical] SOL-ACC-001 - Missing account validation
  File: vulnerable_solana_program.rs.example:22
  Account used without proper validation

[Critical] SOL-ARITH-BAL-SUBTRACTION - Unsafe subtraction on balance
  File: vulnerable_solana_program.rs.example:37
  Unsafe subtraction operation detected on balance value

[High] SOL-SIGN-TRANSFER - Missing signer verification
  File: vulnerable_solana_program.rs.example:42
  Transfer operation found without prior signer verification
```

## Available Commands

| Command | Description | Example |
|---|---|---|
| `analyze` | Comprehensive security and quality analysis | `shieldcontract analyze ./contracts/ --fabric` |
| `scan` | Quick vulnerability scanning | `shieldcontract scan ./contracts/ --fabric` |
| `audit` | Compliance and standards checking | `shieldcontract audit ./contracts/ --fabric` |
| `validate` | AI-generated code validation | `shieldcontract validate ./contract.go` |
| `benchmark` | Performance analysis and benchmarking | `shieldcontract benchmark ./contracts/ --fabric` |
| `report` | Generate detailed report from analysis | `shieldcontract report results.json -o report.html` |
| `optimize` | AI-powered performance optimization suggestions | `shieldcontract optimize ./contracts/` |
| `init` | Create default configuration file | `shieldcontract init` |
| `auth` | Manage AI integrations and API keys | `shieldcontract auth set openai --key sk-...` |
| `history` | Show analysis history | `shieldcontract history` |
| `rules` | Manage custom rules | `shieldcontract rules list` |
| `interactive` | Interactive mode with live validation | `shieldcontract interactive` |

Run `shieldcontract --help` for complete usage information.

## Configuration

Generate a default configuration file:
```bash
shieldcontract init
```

This creates `shieldcontract.toml` with customizable analysis settings.

## Docker Usage

```bash
# Build the Docker image
docker build -t shieldcontract .

# Run analysis on local directory
docker run -v $(pwd):/workspace shieldcontract scan --fabric /workspace/chaincode
```

## Security Analysis Details

### Hyperledger Fabric

**Currently Implemented:**
- **Determinism Checks**: Detects nondeterministic operations (time.Now(), rand, etc.)
- **Global Variables**: Identifies problematic global state usage
- **Private Data**: Basic detection of private data leakage patterns
- **Endorsement Policy**: Checks for basic access control validation
- **MVCC**: Simple detection of potential read conflicts
- **Rich Queries**: Flags non-deterministic query usage

**Check Categories:**
- `FABRIC-ND-001`: Nondeterministic operations
- `FABRIC-GV-001`: Global variable usage
- `FABRIC-EP-001`: Missing endorsement policy validation
- `FABRIC-PD-001`: Private data leakage
- `FABRIC-MVCC-001`: MVCC read conflicts
- `FABRIC-RQ-001`: Rich query usage
- `FABRIC-DOS-001/002`: DoS vulnerabilities

### Solana Programs

**Currently Implemented:**
- **Account Validation**: Detects missing account ownership and signer checks
- **Arithmetic Safety**: Identifies unsafe arithmetic operations
- **CPI Security**: Basic cross-program invocation validation
- **Signer Verification**: Checks for proper authorization
- **Type Safety**: Detects missing discriminator validation
- **Performance**: Identifies excessive logging and compute usage

**Check Categories:**
- `SOL-ACC-001` to `SOL-ACC-006`: Account validation issues
- `SOL-SIGN-*`: Signer verification problems
- `SOL-ARITH-*`: Arithmetic safety issues
- `SOL-CPI-001`: Cross-program invocation vulnerabilities
- `SOL-OWN-001`: Ownership validation issues
- `SOL-TYPE-001`: Type safety problems
- `SOL-PERF-*`: Performance issues

## Output Formats

Supported output formats:
- **Table** (default): Terminal-friendly output
- **JSON**: Machine-readable format
- **HTML**: Web-based report
- **SARIF**: GitHub Security integration

Example:
```bash
shieldcontract analyze ./contracts --format json -o results.json
```

## CI/CD Integration

### GitHub Actions Example
```yaml
- name: Run ShieldContract Analysis
  run: |
    shieldcontract analyze ./chaincode/ \
      --fabric \
      --severity high \
      --exit-code \
      --output-file results.sarif \
      --format sarif

- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

## Development

### Building from Source
```bash
# Development build
cargo build

# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run -- analyze ./examples/
```

## Contributing

We welcome contributions! Please read our `CONTRIBUTING.md` for details on how to submit pull requests and our development setup.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Repository**: [https://github.com/KoushikGavini/ShieldContract](https://github.com/KoushikGavini/ShieldContract)
- **Issues**: [GitHub Issues](https://github.com/KoushikGavini/ShieldContract/issues)
- **Documentation**: See repository documentation for detailed usage examples


