# ChainGuard 🛡️

Advanced security analysis for blockchain platforms with specialized Hyperledger Fabric support.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=flat&logo=rust&logoColor=white)](https://www.rust-lang.org/)

## 🚀 Features

### Hyperledger Fabric Specialization
- **Comprehensive chaincode analysis** for Go, JavaScript, and TypeScript
- **Nondeterminism detection** to ensure consensus compatibility
- **Rich query vulnerability analysis** for CouchDB implementations
- **Global variable misuse detection** preventing state corruption
- **Endorsement policy compliance** validation
- **Private data security** assessment with leakage detection
- **MVCC compliance** checking for concurrent transactions
- **DoS vulnerability** detection in chaincode implementations
- **Channel isolation** security analysis

### AI-Powered Code Validation
- **Multi-LLM integration** with ChatGPT, Claude, and Gemini
- **AI-generated code validation** with determinism checking
- **Hallucination detection** for non-existent dependencies
- **Real-time validation feedback** during development
- **Multi-model consensus** for critical findings
- **Confidence scoring** based on AI agreement levels

### Token Standards Compliance
- **ERC-20** token standard validation
- **ERC-721** NFT implementation checking
- **ERC-1155** multi-token standard compliance
- **ERC-777** advanced token features validation
- **Fabric-adapted** token standards support

### Security Analysis
- **Traditional vulnerabilities**: reentrancy, overflow, underflow
- **Access control** vulnerability detection
- **Business logic** flaw identification
- **Cryptographic** implementation assessment
- **Transaction ordering** dependency analysis
- **Input validation** checking

### Performance & Optimization
- **Transaction throughput** analysis
- **State storage** efficiency evaluation
- **Consensus mechanism** impact assessment
- **Memory usage** pattern analysis
- **AI-powered** optimization suggestions

## 📦 Installation

### Prerequisites
- Rust 1.70+ (install from [rustup.rs](https://rustup.rs/))
- Git
- Optional: Docker for containerized execution

### Build from Source
```bash
# Clone the repository
git clone https://github.com/KoushikGavini/ChainGuard.git
cd ChainGuard

# Build the project
cargo build --release

# Install globally
cargo install --path .
```

### Building from Source is Required
Since this is a source distribution, you'll need to build ChainGuard using Cargo.

## 🔧 Configuration

### Initialize Configuration
```bash
chainguard init
```

### Configure AI Services
```bash
# Set API keys for AI services
chainguard auth set chatgpt --key YOUR_OPENAI_API_KEY
chainguard auth set claude --key YOUR_ANTHROPIC_API_KEY
chainguard auth set gemini --key YOUR_GOOGLE_API_KEY

# Test connections
chainguard auth test --all
```

### Example Configuration (chainguard.toml)
```toml
[analysis]
parallel_analysis = true
max_threads = 8
enable_ai_validation = true
severity_threshold = "medium"

[fabric]
enabled = true
check_determinism = true
check_endorsement = true

[ai]
models = ["chatgpt", "claude", "gemini"]
consensus_threshold = 0.7
cache_responses = true

[token_standards]
validate = ["erc20", "erc721"]
```

## 🎯 Usage

### Basic Commands

#### Comprehensive Analysis
```bash
# Analyze a single file
chainguard analyze path/to/chaincode.go

# Analyze with Fabric-specific checks
chainguard analyze --fabric path/to/chaincode.go

# Analyze directory recursively
chainguard analyze ./contracts/

# With AI validation
chainguard analyze --ai-validate --ai-plugins chatgpt,claude ./contracts/
```

#### Quick Security Scan
```bash
# Quick vulnerability scan
chainguard scan ./contracts/ --severity high

# Fabric-specific scan
chainguard scan --fabric ./chaincode/
```

#### Token Standards Audit
```bash
# Validate ERC-20 compliance
chainguard audit --standards erc20 ./token.sol

# Multiple standards
chainguard audit --standards erc20,erc721,erc1155 ./contracts/
```

#### AI Code Validation
```bash
# Validate AI-generated code
chainguard validate ./ai-generated-contract.go

# With consensus validation
chainguard validate --consensus --consensus-level high ./contract.go
```

#### Performance Benchmarking
```bash
# Full benchmark suite
chainguard benchmark --fabric --throughput --storage --consensus ./chaincode/

# Specific analysis
chainguard benchmark --throughput ./contracts/
```

#### Generate Reports
```bash
# Generate HTML report
chainguard report analysis-results.json -o report.html --format html

# PDF report with remediation guidance
chainguard report results/ -o audit-report.pdf --format pdf --remediation
```

### Advanced Usage

#### Custom Rules
```bash
# Import custom rules
chainguard rules import ./custom-rules.yaml

# List all rules
chainguard rules list --category security

# Enable/disable specific rules
chainguard rules enable FABRIC-SEC-*
chainguard rules disable FABRIC-PERF-001
```

#### CI/CD Integration
```yaml
# GitHub Actions example
- name: Run ChainGuard Analysis
  run: |
    chainguard analyze ./contracts/ \
      --fabric \
      --ai-validate \
      --severity high \
      --exit-code \
      --output-file results.json
```

#### Interactive Mode
```bash
# Start interactive session
chainguard interactive

# With AI assistance
chainguard interactive --ai-assist
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

### IDE Integration
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

### Contributing
Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Hyperledger Fabric community
- OpenAI, Anthropic, and Google for AI capabilities
- Rust community for excellent tooling

## 📞 Support

- **Repository**: [https://github.com/KoushikGavini/ChainGuard](https://github.com/KoushikGavini/ChainGuard)
- **Issues**: [GitHub Issues](https://github.com/KoushikGavini/ChainGuard/issues)
- **Pull Requests**: [Contribute](https://github.com/KoushikGavini/ChainGuard/pulls)

---

**ChainGuard** - Securing the future of blockchain, one smart contract at a time. 🚀 