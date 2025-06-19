# ChainGuard CLI Usage Guide

ChainGuard is a **command-line tool** for blockchain security analysis, designed to be used directly from your terminal.

## Installation as CLI Tool

```bash
# Install directly as a global CLI tool
cargo install --path .

# Building from source is required - no pre-built binaries available

# Verify installation
chainguard --version
```

## Basic CLI Usage

```bash
# Show help
chainguard --help

# Show help for specific command
chainguard analyze --help

# Quick analysis with default settings
chainguard analyze ./my-chaincode.go

# Scan with specific severity threshold
chainguard scan --severity high ./contracts/

# Validate AI-generated code
chainguard validate ./ai-generated-contract.go
```

## Common CLI Workflows

### 1. Daily Security Scan
```bash
# Quick morning security check
chainguard scan ./src --severity high --exit-code

# Full analysis with report
chainguard analyze ./src --fabric --output-file daily-report.json
```

### 2. Pre-commit Hook
```bash
#!/bin/bash
# Add to .git/hooks/pre-commit
chainguard scan --severity high --exit-code $(git diff --cached --name-only)
```

### 3. CI/CD Pipeline
```bash
# In your CI pipeline
chainguard analyze ./contracts \
  --fabric \
  --severity medium \
  --exit-code \
  --output-file results.sarif \
  --output sarif
```

### 4. Batch Processing
```bash
# Analyze multiple directories
for dir in ./contracts/*; do
  chainguard analyze "$dir" --output-file "reports/$(basename $dir).json"
done

# Process with GNU parallel
find . -name "*.go" | parallel -j4 chainguard scan {} --quiet
```

## Output Formats for CLI

ChainGuard supports multiple output formats optimized for terminal use:

```bash
# Default table format (human-readable in terminal)
chainguard analyze ./contract.go

# JSON for scripting
chainguard analyze ./contract.go --output json | jq '.findings[] | select(.severity == "Critical")'

# CSV for spreadsheet import
chainguard analyze ./contract.go --output csv > findings.csv

# SARIF for IDE integration
chainguard analyze ./contract.go --output sarif > results.sarif
```

## CLI Configuration

### Using Config Files
```bash
# Use default config
chainguard analyze ./src

# Use custom config
chainguard analyze ./src --config production.toml

# Initialize config interactively
chainguard init --config my-config.toml
```

### Environment Variables
```bash
# Set API keys via environment
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."

# Set default options
export CHAINGUARD_SEVERITY="high"
export CHAINGUARD_OUTPUT="json"

# Run with env vars
chainguard analyze ./src
```

## Advanced CLI Features

### 1. Watch Mode (File Monitoring)
```bash
# Watch for changes and re-analyze
chainguard analyze ./src --watch

# Watch with notifications
chainguard analyze ./src --watch --notify
```

### 2. Parallel Analysis
```bash
# Use all CPU cores
chainguard analyze ./large-project --parallel

# Specify thread count
chainguard analyze ./large-project --parallel --threads 8
```

### 3. Incremental Analysis
```bash
# Only analyze changed files since last run
chainguard analyze ./src --incremental

# Compare against baseline
chainguard analyze ./src --baseline previous-results.json
```

### 4. Filtering and Queries
```bash
# Include only specific files
chainguard analyze ./src --include "**/*.go" --exclude "**/test_*.go"

# Filter by rule categories
chainguard analyze ./src --rules security,performance

# Disable specific rules
chainguard rules disable FABRIC-PERF-* 
chainguard analyze ./src
```

## CLI Output Examples

### Table Format (Default)
```
ChainGuard Analysis Report - 2024-01-15T10:30:00Z
================================================================================
Total Findings: 15
Critical: 3 | High: 5 | Medium: 4 | Low: 3 | Info: 0
--------------------------------------------------------------------------------

[CRITICAL] FABRIC-SEC-001 - Nondeterministic operation detected
  File: chaincode/asset.go:45
  Use of time.Now() can lead to nondeterministic behavior in chaincode.

[HIGH] FABRIC-SEC-002 - Global variable detected
  File: chaincode/asset.go:12
  Global variable 'assetCounter' can cause nondeterministic behavior.

[HIGH] TOKEN-SEC-001 - Missing overflow protection
  File: token/erc20.go:78
  Token arithmetic operations lack overflow protection.
```

### JSON Format (for Automation)
```bash
chainguard analyze ./src --output json --quiet | \
  jq -r '.findings[] | "\(.severity): \(.title) at \(.file):\(.line)"'
```

### Interactive Mode
```bash
# Start interactive session
chainguard interactive

# Interactive with working directory
chainguard interactive ./my-project
```

## Shell Completion

```bash
# Bash
chainguard completions bash > /etc/bash_completion.d/chainguard

# Zsh
chainguard completions zsh > ~/.zsh/completions/_chainguard

# Fish
chainguard completions fish > ~/.config/fish/completions/chainguard.fish
```

## Exit Codes

ChainGuard uses standard exit codes for scripting:

- `0`: Success, no issues found
- `1`: Issues found (when using --exit-code)
- `2`: Invalid arguments or configuration
- `3`: Analysis error
- `4`: File not found
- `5`: Authentication error

```bash
# Check exit code in scripts
if chainguard scan ./src --exit-code; then
  echo "No critical issues found"
else
  echo "Issues detected, check the report"
  exit 1
fi
```

## Performance Tips for CLI Usage

1. **Use Quick Scan for Large Codebases**
   ```bash
   # Fast security check
   chainguard scan ./large-project --parallel
   ```

2. **Cache Results**
   ```bash
   # Enable caching for faster subsequent runs
   chainguard analyze ./src --cache
   ```

3. **Selective Analysis**
   ```bash
   # Only analyze modified files
   git diff --name-only | xargs chainguard analyze
   ```

## Troubleshooting CLI Issues

```bash
# Verbose output for debugging
chainguard analyze ./src --verbosity debug

# Dry run to see what would be analyzed
chainguard analyze ./src --dry-run

# Check configuration
chainguard config validate

# Test AI connections
chainguard auth test --all
```

## Integration with Other CLI Tools

```bash
# Pipe to other tools
chainguard analyze ./src --output json | jq '.findings[] | select(.severity == "Critical")'

# Use with grep
chainguard analyze ./src 2>&1 | grep -E "CRITICAL|HIGH"

# Generate and open HTML report
chainguard report results.json -o report.html && open report.html

# Send results to monitoring
chainguard analyze ./src --output json | curl -X POST https://monitor.example.com/api/results -d @-
```

ChainGuard is built from the ground up as a CLI tool, designed to integrate seamlessly into your terminal workflow, build pipelines, and automation scripts. 