# ShieldContract Report Generation Features

ShieldContract provides comprehensive report generation capabilities in multiple formats to suit different needs.

## Available Report Formats

### 1. **JSON Format** (Working)
Perfect for CI/CD integration and programmatic processing.

```bash
./target/release/shieldcontract analyze test_chaincode.go --fabric -o json --output-file report.json
```

**Features:**
- Machine-readable format
- Complete finding details with metadata
- Easy integration with other tools
- Includes confidence scores and AI consensus data

### 2. **Markdown Format** (Working)
Great for documentation and GitHub/GitLab integration.

```bash
./target/release/shieldcontract analyze test_chaincode.go --fabric -o markdown --output-file report.md
```

**Features:**
- Human-readable format
- GitHub/GitLab compatible
- Includes code snippets with syntax highlighting
- Executive summary with key metrics

### 3. **Table Format** (Default)
Console-friendly output for quick reviews.

```bash
./target/release/shieldcontract analyze test_chaincode.go --fabric
```

**Features:**
- Colored terminal output
- Summary statistics
- Progress indicators
- Immediate feedback

### 4. **HTML Format** (🔧 Template issue)
Interactive web-based reports.

```bash
# Currently has a template rendering issue with the "lowercase" helper
./target/release/shieldcontract analyze test_chaincode.go --fabric -o html --output-file report.html
```

### 5. **Other Formats** (📋 Planned)
- **PDF**: Professional reports for compliance
- **CSV**: Spreadsheet-compatible data export
- **XML**: Enterprise integration
- **SARIF**: GitHub Advanced Security integration

## Report Contents

All reports include:

### Metadata Section
- Tool version
- Timestamp
- Files analyzed
- Analysis duration
- Total lines of code

### Summary Section
- Total findings by severity
- Security score (0-100)
- AI validation score (0-100)
- Complexity score (0-100)
- Performance metrics

### Detailed Findings
Each finding includes:
- Unique ID
- Severity level (Critical/High/Medium/Low/Info)
- Category (security/performance/complexity/ai-generated)
- Title and description
- File location (file:line:column)
- Code snippet
- Remediation suggestions
- Reference links
- Confidence score
- AI consensus (if multiple AI models used)

### Recommendations Section
- Prioritized action items
- Best practices
- Optimization suggestions

## Using the Dedicated Report Command

Generate reports from saved analysis results:

```bash
# First, save analysis results
./target/release/shieldcontract analyze project/ --output-file results.json

# Then generate reports in different formats
./target/release/shieldcontract report results.json -f markdown -o report.md
./target/release/shieldcontract report results.json -f html -o report.html --remediation --examples
```

## Integration Examples

### CI/CD Pipeline
```yaml
# GitHub Actions example
- name: Run ShieldContract Analysis
  run: |
    ./shieldcontract analyze src/ -o json --output-file analysis.json
    ./shieldcontract report analysis.json -f sarif -o results.sarif
    
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### Automated Reporting
```bash
# Generate daily security reports
./shieldcontract analyze contracts/ \
  --fabric \
  --ai-validate \
  -o markdown \
  --output-file "reports/security-$(date +%Y%m%d).md"
```

## Sample Report Output

Here's what a finding looks like in JSON format:

```json
{
  "id": "SEC-ND-TIMESTAMP_USAGE",
  "severity": "High",
  "category": "security/nondeterminism",
  "title": "Nondeterministic pattern: timestamp_usage",
  "description": "System timestamps are non-deterministic across peers",
  "file": "test_chaincode.go",
  "line": 1,
  "column": 48,
  "code_snippet": "1 | package main; import \"time\"; func main() { t := time.Now();",
  "remediation": "Use transaction timestamp from stub.GetTxTimestamp()",
  "references": ["https://hyperledger-fabric.readthedocs.io/..."],
  "confidence": 0.95,
  "ai_consensus": null
}
```

## Next Steps

1. Fix the HTML template helper issue for interactive reports
2. Implement PDF generation for compliance documentation
3. Add SARIF format for GitHub integration
4. Create custom report templates for specific use cases 