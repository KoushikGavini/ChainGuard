# GitHub Repository Settings

## Description
Advanced security analysis and AI code review platform for blockchain smart contracts. Supports Hyperledger Fabric and Solana with 50+ vulnerability detectors.

## Topics
- blockchain
- security
- smart-contracts
- solana
- hyperledger-fabric
- rust
- security-audit
- static-analysis
- vulnerability-scanner
- code-review
- ai-powered
- chaincode
- defi

## Website
https://crates.io/crates/chainguard

## Settings to Enable
- ✅ Issues
- ✅ Projects
- ✅ Wiki
- ✅ Discussions
- ✅ Sponsorships
- ✅ Preserve this repository
- ✅ Include in the home page "Trending" feed

## Branch Protection Rules (for main branch)
- ✅ Require a pull request before merging
- ✅ Require status checks to pass before merging
  - Required checks: CI, Clippy, Rustfmt
- ✅ Require branches to be up to date before merging
- ✅ Include administrators
- ✅ Allow force pushes (for maintainers only)

## Security Settings
- ✅ Dependency graph
- ✅ Dependabot alerts
- ✅ Dependabot security updates
- ✅ Code scanning alerts
- ✅ Secret scanning alerts

## Pages Settings
- Source: Deploy from a branch
- Branch: main
- Folder: /docs (when documentation is added)

## Secrets Required
- `CRATES_IO_TOKEN` - For publishing to crates.io
- `CODECOV_TOKEN` - For code coverage reporting (optional) 