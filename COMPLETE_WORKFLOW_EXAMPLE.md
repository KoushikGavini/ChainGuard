# ChainGuard Complete Workflow Example

This example demonstrates a complete security analysis workflow using ChainGuard with AI features.

## Scenario

A development team needs to analyze their Hyperledger Fabric chaincode before deployment.

## Step 1: Install ChainGuard

```bash
# Clone and build from source
git clone https://github.com/KoushikGavini/ChainGuard.git
cd ChainGuard
cargo install --path .

# Verify installation
chainguard --version
```

## Step 2: Configure AI Services

```bash
# Set up API keys for AI services
chainguard auth set openai --key $OPENAI_API_KEY
chainguard auth set claude --key $CLAUDE_API_KEY
chainguard auth set gemini --key $GEMINI_API_KEY

# Test connections
chainguard auth test --all
```

## Step 3: Initial Security Scan

```bash
# Quick scan to identify critical issues
chainguard scan ./chaincode/ --severity critical

# Output:
# 🛡️  ChainGuard v1.0.0 - Quick Security Scan
# 
# Scanning 5 files...
# 
# ❌ CRITICAL: 5 issues found
#   - Nondeterministic time usage (2 instances)
#   - Random number generation (1 instance)
#   - External HTTP calls (1 instance)
#   - Private data leak (1 instance)
```

## Step 4: Comprehensive Analysis with AI

```bash
# Full analysis with AI consensus
chainguard analyze ./chaincode/asset_transfer.go \
  --fabric \
  --ai-validate \
  --consensus \
  --output-file analysis.json

# Output:
# 🤖 Running AI-powered analysis with consensus...
# 
# ChatGPT: Analyzing... ✓
# Claude: Analyzing... ✓
# Gemini: Analyzing... ✓
# 
# Consensus achieved: 87%
# Total issues: 13 (5 critical, 3 high, 3 medium, 2 low)
```

## Step 5: Validate AI-Generated Code

```bash
# Check if any code appears to be AI-generated
chainguard validate ./chaincode/ --consensus

# Output:
# AI Generation Likelihood: 45% (Moderate)
# Hallucinations Found: 0
# Quality Score: 72/100
```

## Step 6: Interactive Analysis

```bash
# Start interactive mode for detailed investigation
chainguard interactive --ai-assist

# Example session:
chainguard> analyze asset_transfer.go
# 13 issues found

chainguard> explain issue FABRIC-SEC-001
# AI: This issue occurs because time.Now() returns different 
# values on different peers, breaking consensus...

chainguard> show fix
# AI: Replace time.Now() with stub.GetTxTimestamp()...

chainguard> apply fix FABRIC-SEC-001
# ✓ Fix applied to asset_transfer.go
```

## Step 7: Generate Fixes

```bash
# Generate all recommended fixes
chainguard analyze ./chaincode/ --fix --output fixes.patch

# Review fixes
cat fixes.patch

# Apply fixes after review
chainguard apply-fixes fixes.patch --interactive
```

## Step 8: Token Standards Compliance

```bash
# Check ERC-20 compliance for token chaincode
chainguard audit ./token_chaincode.go --standards erc20,erc721

# Output:
# Token Standards Audit
# ====================
# ERC-20 Compliance: 85% (Missing: decimals(), symbol())
# ERC-721 Compliance: N/A (Not an NFT implementation)
```

## Step 9: Performance Analysis

```bash
# Analyze performance characteristics
chainguard benchmark ./chaincode/ --fabric --throughput --storage

# Output:
# Performance Analysis
# ===================
# Estimated TPS: 500-800
# State Storage: Efficient (composite keys used)
# Query Performance: ⚠️  Unbounded queries detected
```

## Step 10: Generate Reports

```bash
# Generate comprehensive report
chainguard report analysis.json \
  --format pdf \
  --include-fixes \
  --include-ai-consensus \
  --output security_audit.pdf

# Generate CI/CD compatible report
chainguard report analysis.json \
  --format sarif \
  --output results.sarif
```

## Step 11: Re-scan After Fixes

```bash
# Verify all critical issues are resolved
chainguard scan ./chaincode/ --severity critical

# Output:
# ✅ No critical issues found!
# 
# Remaining issues:
#   High: 1
#   Medium: 2
#   Low: 2
```

## Step 12: Final Validation

```bash
# Final check before deployment
chainguard analyze ./chaincode/ \
  --fabric \
  --exit-code \
  --severity high

# Exit code 0 = ready for deployment
echo $?  # 0
```

## Summary

This workflow demonstrates:
1. **Installation and setup**
2. **AI service configuration**
3. **Quick security scanning**
4. **Comprehensive AI-powered analysis**
5. **AI code validation**
6. **Interactive investigation**
7. **Automated fix generation**
8. **Standards compliance checking**
9. **Performance analysis**
10. **Professional reporting**
11. **Verification of fixes**
12. **CI/CD integration**

## Key Commands Reference

```bash
# Setup
chainguard auth set <service> --key <key>

# Analysis
chainguard analyze <path> --fabric --ai-validate --consensus

# Validation
chainguard validate <path> --consensus

# Interactive
chainguard interactive --ai-assist

# Fixes
chainguard analyze <path> --fix --apply

# Reports
chainguard report <results> --format <format>
```

With ChainGuard's AI-powered features, teams can ensure their blockchain code is secure, compliant, and ready for production deployment. 