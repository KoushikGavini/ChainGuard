# ChainGuard Architecture

## Overview

ChainGuard is a modular security analysis platform for blockchain smart contracts. It's designed to be extensible, allowing easy addition of new blockchain platforms, analysis rules, and AI providers.

## Project Structure

```
chainguard/
├── src/
│   ├── main.rs              # CLI entry point
│   ├── lib.rs               # Library exports
│   ├── analyzer/            # Core analysis engines
│   │   ├── mod.rs           # Analyzer trait and implementations
│   │   ├── security.rs      # Security vulnerability detection
│   │   ├── performance.rs   # Performance analysis
│   │   ├── complexity.rs    # Code complexity metrics
│   │   └── dependencies.rs  # Dependency analysis
│   ├── fabric/              # Hyperledger Fabric specific
│   │   ├── mod.rs           # Fabric analyzer implementation
│   │   ├── determinism.rs   # Non-deterministic pattern detection
│   │   ├── endorsement.rs   # Endorsement policy analysis
│   │   ├── performance.rs   # Fabric-specific performance
│   │   ├── private_data.rs  # Private data collection checks
│   │   └── state_db.rs      # State database usage analysis
│   ├── solana/              # Solana specific
│   │   ├── mod.rs           # Solana analyzer implementation
│   │   ├── account_validation.rs   # Account validation checks
│   │   ├── arithmetic_checks.rs    # Overflow/underflow detection
│   │   ├── cpi_security.rs         # Cross-program invocation security
│   │   ├── ownership_validation.rs # Program ownership checks
│   │   ├── performance.rs          # Compute unit optimization
│   │   └── signer_checks.rs        # Signer verification
│   ├── llm/                 # AI/LLM integration
│   │   └── mod.rs           # LLM provider trait and manager
│   ├── reporter/            # Report generation
│   │   ├── mod.rs           # Reporter trait and implementations
│   │   └── templates/       # Report templates (HTML, MD)
│   ├── rules/               # Rule engine
│   │   └── mod.rs           # Rule loading and execution
│   ├── token_standards/     # Token standard compliance
│   │   ├── mod.rs           # Token standard trait
│   │   ├── erc20.rs         # ERC-20 compliance (stub)
│   │   ├── erc721.rs        # ERC-721 compliance (stub)
│   │   └── stablecoin.rs    # Stablecoin-specific checks
│   ├── utils/               # Utility functions
│   │   └── mod.rs           # File handling, code snippets
│   └── validator/           # Input validation
│       ├── mod.rs           # Validator trait
│       ├── ai_patterns.rs   # AI hallucination detection
│       ├── dependency_validator.rs # Package validation
│       └── slopsquatting.rs # Typosquatting detection
├── examples/                # Example vulnerable contracts
├── tests/                   # Integration tests
└── docs/                    # Documentation

```

## Core Design Principles

### 1. **Modularity**
Each blockchain platform has its own module with platform-specific analyzers. Common functionality is shared through traits.

### 2. **Extensibility**
New platforms can be added by:
- Creating a new module in `src/`
- Implementing the `Analyzer` trait
- Adding platform-specific rules

### 3. **Performance**
- Parallel analysis using Rayon
- Efficient AST traversal with Tree-sitter
- Caching of analysis results

### 4. **Security**
- Sandboxed execution for untrusted code
- API key encryption
- No network calls during analysis (except for AI validation)

## Key Components

### Analyzer Trait
```rust
#[async_trait]
pub trait Analyzer: Send + Sync {
    async fn analyze(&self, path: &Path, config: &Config) -> Result<Vec<Finding>>;
    fn supported_extensions(&self) -> Vec<&str>;
    fn name(&self) -> &str;
}
```

### Finding Structure
```rust
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub category: String,
    pub title: String,
    pub description: String,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub code_snippet: Option<String>,
    pub remediation: Option<String>,
    pub references: Vec<String>,
    pub ai_consensus: Option<AIConsensus>,
}
```

### Adding a New Platform

1. Create a new module in `src/your_platform/`
2. Implement the `Analyzer` trait
3. Add platform-specific sub-analyzers
4. Register in `main.rs`
5. Add tests in `tests/your_platform/`

### Adding New Rules

1. Define rules in YAML/JSON format
2. Place in `rules/your_platform/`
3. Rules are loaded automatically

### Adding AI Providers

1. Implement the `LLMProvider` trait
2. Add to `src/llm/`
3. Handle authentication in `AuthManager`

## Testing Strategy

- Unit tests for each analyzer
- Integration tests for CLI commands
- Example vulnerable contracts for validation
- Benchmark tests for performance

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines. 