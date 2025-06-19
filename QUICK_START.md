# ChainGuard CLI - Quick Start

ChainGuard is a **command-line tool** for blockchain security analysis. This guide gets you up and running in 5 minutes.

## 1. Install the CLI

```bash
# Option A: Build from source
git clone https://github.com/KoushikGavini/ChainGuard.git
cd ChainGuard
cargo install --path .

# Building from source is the only installation method

# Verify it works
chainguard --version
```

## 2. Quick Security Scan (No Config Needed!)

```bash
# Scan a single file
chainguard scan vulnerable_chaincode.go

# Scan a directory
chainguard scan ./contracts/

# Only show critical issues
chainguard scan ./contracts/ --severity critical
```

## 3. Full Analysis

```bash
# Analyze with Fabric-specific checks
chainguard analyze ./chaincode/ --fabric

# Save results to file
chainguard analyze ./chaincode/ --output-file results.json

# Generate HTML report
chainguard analyze ./chaincode/ --output-file report.html --output html
```

## 4. Common One-Liners

```bash
# Pre-commit check
chainguard scan --severity high --exit-code $(git diff --cached --name-only)

# CI/CD pipeline
chainguard analyze . --fabric --severity medium --exit-code --output sarif > results.sarif

# Find critical issues only
chainguard scan . --output json | jq '.findings[] | select(.severity == "Critical")'

# Count issues by severity
chainguard analyze . --output json | jq '.findings | group_by(.severity) | map({severity: .[0].severity, count: length})'

# Analyze only Go files modified in last commit
git diff --name-only HEAD~1 | grep '\.go$' | xargs chainguard analyze
```

## 5. Set Up AI Features (Optional)

```bash
# Configure OpenAI
chainguard auth set openai --key YOUR_API_KEY

# Test connection
chainguard auth test openai

# Run with AI validation
chainguard validate ./ai-generated-contract.go --consensus
```

## That's It! 🚀

You're now ready to use ChainGuard. For more options:

```bash
# See all commands
chainguard --help

# Get help for a specific command
chainguard analyze --help

# View all examples
cat CLI_USAGE.md
```

**ChainGuard is a CLI tool** - no libraries to import, no APIs to learn. Just run it from your terminal! 