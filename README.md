# ChainGuard 🛡️

An advanced analysis and review platform for smart contracts and blockchain applications. ChainGuard is designed for the modern development workflow, providing the tools to ensure that any code—whether human-written or AI-generated—is secure, efficient, and correct. It includes specialized support for Hyperledger Fabric chaincode alongside broad capabilities for other platforms.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=flat&logo=rust&logoColor=white)](https://www.rust-lang.org/)

## Key Features

- **Review and Harden AI-Generated Code**: The core of ChainGuard. It's designed to help developers review, validate, and harden smart contracts produced by AI, catching subtle flaws, hallucinations, and vulnerabilities that models can introduce.
- **Multi-LLM Consensus Analysis**: Plug in API keys for multiple LLM providers (ChatGPT, Claude, Gemini) to get a robust, consensus-based analysis. This is critical for validating the logic and security of AI-generated code.
- **Comprehensive Smart Contract Auditing**: Goes beyond security to analyze for correctness, performance bottlenecks, and compliance with best practices.
- **Stablecoin Security Analysis**: Specialized checks for stablecoin contracts including collateralization, oracle security, minting controls, flash loan protection, and peg stability mechanisms.
- **Hyperledger Fabric Support**: Analysis of Fabric chaincode for common issues including nondeterministic operations (timestamps, randomness, global state), potential private data exposure, basic MVCC conflict detection, and platform-specific vulnerabilities.
- **Performance & Optimization Insights**: Analyzes transaction throughput and storage efficiency, providing actionable, AI-powered suggestions for optimization.
- **Flexible Reporting**: Generates detailed reports in JSON, Markdown, HTML, and SARIF to integrate seamlessly into your development and CI/CD workflows.

## Installation

### Prerequisites
- **Rust (1.70+):** Install via [rustup.rs](https://rustup.rs/).
- **Git:** For cloning the repository.
- **Z3 Solver (for formal verification):**
  ```bash
  # macOS
  brew install z3
  # Ubuntu/Debian
  sudo apt-get install z3
  ```

### Build from Source
Building from source is the recommended way to install ChainGuard.

```bash
# 1. Clone the repository
git clone https://github.com/KoushikGavini/ChainGuard.git
cd ChainGuard

# 2. Build the release binary
cargo build --release

# The executable will be at ./target/release/chainguard
./target/release/chainguard --version
```

For convenience, you can add the target directory to your path or install it globally:
```bash
# Install globally using cargo
cargo install --path .

# Now you can run it from anywhere
chainguard --version
```

## Getting Started: A Quick Example

Once installed, you can immediately run a scan on the provided test file to see ChainGuard in action.

### Run Your First Scan

From the root of the project directory, run the following command after building the tool:

```bash
./target/release/chainguard analyze test_chaincode.go --fabric
```

This command analyzes the sample Go chaincode file (`test_chaincode.go`) using ChainGuard's Hyperledger Fabric-specific rules.

### Expected Output

You will see a summary of the findings directly in your terminal, similar to this:

```text
🔍 Chainguard Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
...
ChainGuard Analysis Report
==========================
Total Findings: 2
Critical: 0 | High: 2 | Medium: 0 | Low: 0 | Info: 0

[High] SEC-ND-TIMESTAMP_USAGE - Nondeterministic pattern: timestamp_usage
  File: test_chaincode.go:1
  System timestamps are non-deterministic across peers

[High] SEC-ACCESS-001 - Missing access control implementation
  File: test_chaincode.go:1
  No authentication or authorization checks found
```

This gives you immediate feedback that the tool is working correctly. You can now point ChainGuard at your own projects.

## Common Commands

ChainGuard offers a rich set of commands for different analysis needs.

| Command | Description | Example |
|---|---|---|
| `analyze` | Comprehensive security, performance, and quality analysis. | `chainguard analyze --fabric ./my-chaincode/` |
| `scan` | Quick scan for high-severity vulnerabilities. | `chainguard scan ./contracts/` |
| `audit` | Check for compliance with standards like ERC-20. | `chainguard audit --standards erc20 ./token.sol` |
| `audit` | Check stablecoin-specific security issues. | `chainguard audit --standards stablecoin ./stablecoin.sol` |
| `validate` | Use multiple LLMs to review and validate code for correctness. | `chainguard validate --consensus ./contract.go` |
| `benchmark` | Analyze performance metrics like throughput and storage. | `chainguard benchmark --throughput ./chaincode/` |
| `report` | Generate a detailed report from a previous analysis. | `chainguard report results.json -o report.html` |
| `init` | Create a default `chainguard.toml` configuration file. | `chainguard init` |

Run `chainguard --help` or `chainguard <COMMAND> --help` for a full list of options.

## AI-Powered Review and Analysis

ChainGuard's AI capabilities are designed to augment the developer's review process, not replace it. To enable these features, you need to configure API keys for one or more supported LLM providers.

### 1. Configure API Keys
You can connect multiple LLM providers to ChainGuard. API keys are stored securely in `~/.chainguard/auth.toml`.

```bash
# Set API keys for your preferred AI services
chainguard auth set openai --key sk-...
chainguard auth set claude --key ...
chainguard auth set gemini --key ...

# Test the connection to all configured services
chainguard auth test
```

### 2. Run AI-Assisted Review
Use the `validate` command to specifically review AI-generated code, or use the `--ai-validate` flag during a full analysis to incorporate AI-driven checks.

```bash
# Review AI-generated code for correctness, hallucinations, and vulnerabilities
chainguard validate ./ai-generated-contract.go

# Run a full analysis, including an AI-powered review with multiple LLMs
chainguard analyze --ai-validate --ai-plugins chatgpt,claude ./contracts/
```

## CI/CD Integration

ChainGuard can be easily integrated into your CI/CD pipeline to automate security checks. Use the `--exit-code` flag to have the process fail if high-severity findings are detected.

### GitHub Actions Example
```yaml
- name: Run ChainGuard Analysis
  run: |
    chainguard analyze ./contracts/ \
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

## Configuration

Generate a default `chainguard.toml` file to customize analysis settings.
```bash
chainguard init
```
This file allows you to configure rules, AI models, severity thresholds, and more.

## Docker Usage
You can also run ChainGuard within a Docker container.

```bash
# Build the Docker image
docker build -t chainguard .

# Run analysis on a local directory
docker run -v $(pwd):/workspace chainguard analyze /workspace/my-project
```

## Contributing

We welcome contributions! Please read our `CONTRIBUTING.md` for details on how to submit pull requests, our code of conduct, and development setup.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🏦 Stablecoin Security

ChainGuard includes comprehensive security checks specifically designed for stablecoin contracts:

### Key Stablecoin Checks:
- **Collateralization**: Verifies proper collateral ratio tracking and minimum thresholds
- **Oracle Security**: Detects vulnerable price feeds, single oracle dependencies, and manipulation risks
- **Minting Controls**: Ensures proper access control and supply limits on token creation
- **Emergency Mechanisms**: Checks for pause functionality and timelock governance
- **Peg Stability**: Validates rebalancing mechanisms and redemption functionality
- **Flash Loan Protection**: Identifies reentrancy vulnerabilities and price manipulation risks
- **Reserve Management**: Ensures multi-signature controls and transparent tracking
- **Liquidation Logic**: Verifies proper liquidation mechanisms and incentives

### Example Usage:
```bash
# Analyze a stablecoin contract
chainguard analyze --standards stablecoin ./my-stablecoin.sol

# The analysis will identify issues like:
# - STABLE-COLLAT-001: Missing collateralization mechanism
# - STABLE-ORACLE-001: Unprotected oracle price feed
# - STABLE-MINT-001: Unrestricted minting capability
# - STABLE-FLASH-001: Missing reentrancy protection
```

## 🔍 Analysis Categories

### Security Vulnerabilities
- **FABRIC-SEC-xxx**: Fabric-specific security issues
- **TOKEN-SEC-xxx**: Token-related vulnerabilities
- **CRYPTO-SEC-xxx**: Cryptographic weaknesses
- **ACCESS-xxx**: Access control issues

### Performance Issues
- **PERF-xxx**: General performance problems
- **FABRIC-PERF-xxx**: Fabric-specific performance issues
- **STATE-xxx**: State management inefficiencies

### Compliance Violations
- **ERC20-xxx**: ERC-20 standard violations
- **ERC721-xxx**: ERC-721 standard violations
- **FABRIC-COMP-xxx**: Fabric best practices violations

## 🤝 Integration

### IDE Integration [Coming Soon]
- **VSCode**: Install the ChainGuard extension
- **IntelliJ**: Available in JetBrains marketplace
- **Vim**: Use the chainGuard.vim plugin

### Git Hooks
```bash
# Add pre-commit hook
echo '#!/bin/sh
chainguard analyze --exit-code $(git diff --cached --name-only --diff-filter=ACM | grep -E "\.(go|js|ts|sol)$")
' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### Docker Usage
```bash
# Run in Docker
docker run -v $(pwd):/workspace chainguard/chainguard:latest analyze /workspace

# With AI services
docker run -e OPENAI_API_KEY=$OPENAI_API_KEY \
  -v $(pwd):/workspace \
  chainguard/chainguard:latest analyze --ai-validate /workspace
```

## 📊 Output Formats

ChainGuard supports multiple output formats:
- **Table** (default): Human-readable terminal output
- **JSON**: Machine-readable format for tooling
- **HTML**: Interactive web report
- **PDF**: Professional audit reports
- **SARIF**: GitHub/GitLab integration
- **CSV**: Spreadsheet analysis
- **XML**: Legacy tool integration
- **Markdown**: Documentation-friendly format

## 🛠️ Development

### Building from Source
```bash
# Development build
cargo build

# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run -- analyze ./test-contracts/
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


## 📞 Support

- **Repository**: [https://github.com/KoushikGavini/ChainGuard](https://github.com/KoushikGavini/ChainGuard)
- **Issues**: [GitHub Issues](https://github.com/KoushikGavini/ChainGuard/issues)
- **Pull Requests**: [Contribute](https://github.com/KoushikGavini/ChainGuard/pulls)

---

**ChainGuard** - Securing the future of blockchain, one smart contract at a time. 
