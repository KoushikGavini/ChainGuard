use crate::{Finding, Result, Severity, FabricGuardError};
use regex::Regex;
use std::path::Path;
use tree_sitter::{Parser, Query, QueryCursor};

pub struct SecurityAnalyzer {
    parser: Parser,
    nondeterminism_patterns: Vec<NondeterminismPattern>,
    concurrency_patterns: Vec<ConcurrencyPattern>,
    ledger_patterns: Vec<LedgerPattern>,
    patterns: Vec<SecurityPattern>,
}

#[derive(Debug)]
struct NondeterminismPattern {
    name: String,
    regex: Regex,
    severity: Severity,
    description: String,
    remediation: String,
}

#[derive(Debug)]
struct ConcurrencyPattern {
    name: String,
    query: String,
    severity: Severity,
    description: String,
}

#[derive(Debug)]
struct LedgerPattern {
    name: String,
    regex: Regex,
    severity: Severity,
    description: String,
}

struct SecurityPattern {
    id: String,
    pattern: Regex,
    severity: Severity,
    title: String,
    description: String,
    remediation: String,
}

impl SecurityAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser.set_language(tree_sitter_go::language()).expect("Error loading Go grammar");
        
        let nondeterminism_patterns = vec![
            NondeterminismPattern {
                name: "random_usage".to_string(),
                regex: Regex::new(r"math/rand|crypto/rand|rand\.\w+").unwrap(),
                severity: Severity::Critical,
                description: "Random number generation breaks determinism in chaincode".to_string(),
                remediation: "Use deterministic values from transaction context or ledger state".to_string(),
            },
            NondeterminismPattern {
                name: "timestamp_usage".to_string(),
                regex: Regex::new(r"time\.Now\(\)|time\.Unix|time\.Date").unwrap(),
                severity: Severity::High,
                description: "System timestamps are non-deterministic across peers".to_string(),
                remediation: "Use transaction timestamp from stub.GetTxTimestamp()".to_string(),
            },
            NondeterminismPattern {
                name: "map_iteration".to_string(),
                regex: Regex::new(r"for\s+\w+\s*,?\s*\w*\s*:=\s*range\s+\w+\s*\{").unwrap(),
                severity: Severity::Medium,
                description: "Map iteration order is non-deterministic in Go".to_string(),
                remediation: "Sort map keys before iteration or use ordered data structures".to_string(),
            },
            NondeterminismPattern {
                name: "external_api_call".to_string(),
                regex: Regex::new(r"http\.Get|http\.Post|net\.Dial|rpc\.").unwrap(),
                severity: Severity::Critical,
                description: "External API calls break determinism and consensus".to_string(),
                remediation: "Use oracles or off-chain data through deterministic methods".to_string(),
            },
            NondeterminismPattern {
                name: "file_system_access".to_string(),
                regex: Regex::new(r"os\.Open|ioutil\.ReadFile|os\.Create|os\.WriteFile").unwrap(),
                severity: Severity::Critical,
                description: "File system operations are non-deterministic".to_string(),
                remediation: "Store data in the ledger or use chaincode lifecycle for static data".to_string(),
            },
        ];
        
        let concurrency_patterns = vec![
            ConcurrencyPattern {
                name: "goroutine_usage".to_string(),
                query: r#"(go_statement) @goroutine"#.to_string(),
                severity: Severity::Critical,
                description: "Goroutines introduce non-deterministic execution".to_string(),
            },
            ConcurrencyPattern {
                name: "global_variable".to_string(),
                query: r#"(var_declaration (var_spec name: (identifier) @name)) @var"#.to_string(),
                severity: Severity::High,
                description: "Global variables can cause race conditions".to_string(),
            },
            ConcurrencyPattern {
                name: "channel_usage".to_string(),
                query: r#"(channel_type) @channel"#.to_string(),
                severity: Severity::High,
                description: "Channel operations can introduce non-determinism".to_string(),
            },
        ];
        
        let ledger_patterns = vec![
            LedgerPattern {
                name: "phantom_read".to_string(),
                regex: Regex::new(r"GetStateByRange|GetStateByPartialCompositeKey").unwrap(),
                severity: Severity::Medium,
                description: "Range queries are susceptible to phantom reads".to_string(),
            },
            LedgerPattern {
                name: "missing_mvcc_check".to_string(),
                regex: Regex::new(r"PutState.*GetState").unwrap(),
                severity: Severity::Medium,
                description: "Potential MVCC conflict without proper validation".to_string(),
            },
            LedgerPattern {
                name: "private_data_leak".to_string(),
                regex: Regex::new(r"GetPrivateData.*PutState|fmt\.Print.*GetPrivateData").unwrap(),
                severity: Severity::Critical,
                description: "Private data may be exposed to unauthorized parties".to_string(),
            },
        ];
        
        let patterns = vec![
            SecurityPattern {
                id: "SEC-VULN-001".to_string(),
                pattern: Regex::new(r"(?i)(password|secret|key)\s*=\s*[\"'][^\"']+[\"']").unwrap(),
                severity: Severity::Critical,
                title: "Hardcoded credentials detected".to_string(),
                description: "Hardcoded passwords or secrets found in code".to_string(),
                remediation: "Use environment variables or secure key management systems".to_string(),
            },
            SecurityPattern {
                id: "SEC-VULN-002".to_string(),
                pattern: Regex::new(r"(?i)eval\s*\(").unwrap(),
                severity: Severity::Critical,
                title: "Code injection vulnerability".to_string(),
                description: "Use of eval() can lead to code injection attacks".to_string(),
                remediation: "Avoid eval() and use safer alternatives".to_string(),
            },
            SecurityPattern {
                id: "SEC-VULN-003".to_string(),
                pattern: Regex::new(r"(?i)(sql|query)\s*\+\s*").unwrap(),
                severity: Severity::High,
                title: "Potential SQL injection".to_string(),
                description: "String concatenation in SQL queries detected".to_string(),
                remediation: "Use parameterized queries or prepared statements".to_string(),
            },
            SecurityPattern {
                id: "SEC-VULN-004".to_string(),
                pattern: Regex::new(r"http://").unwrap(),
                severity: Severity::Medium,
                title: "Insecure HTTP connection".to_string(),
                description: "Using HTTP instead of HTTPS for network communication".to_string(),
                remediation: "Use HTTPS for all network communications".to_string(),
            },
            SecurityPattern {
                id: "SEC-VULN-005".to_string(),
                pattern: Regex::new(r"(?i)unsafe").unwrap(),
                severity: Severity::High,
                title: "Unsafe operation detected".to_string(),
                description: "Use of unsafe operations that could compromise security".to_string(),
                remediation: "Review and replace unsafe operations with safe alternatives".to_string(),
            },
        ];
        
        Self {
            parser,
            nondeterminism_patterns,
            concurrency_patterns,
            ledger_patterns,
            patterns,
        }
    }

    pub fn analyze(&self, content: &str, path: &Path) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for nondeterminism patterns
        for pattern in &self.nondeterminism_patterns {
            for mat in pattern.regex.find_iter(content) {
                let line_number = content[..mat.start()].lines().count();
                findings.push(Finding {
                    id: format!("SEC-ND-{}", pattern.name.to_uppercase()),
                    severity: pattern.severity,
                    category: "security/nondeterminism".to_string(),
                    title: format!("Nondeterministic pattern: {}", pattern.name),
                    description: pattern.description.clone(),
                    file: path.display().to_string(),
                    line: line_number,
                    column: mat.start() - content.lines().take(line_number - 1).map(|l| l.len() + 1).sum::<usize>(),
                    code_snippet: Some(extract_code_snippet(content, line_number, 3)),
                    remediation: Some(pattern.remediation.clone()),
                    references: vec![
                        "https://hyperledger-fabric.readthedocs.io/en/latest/chaincode4ade.html".to_string()
                    ],
                });
            }
        }
        
        // Check for concurrency issues using tree-sitter
        let tree = self.parser.parse(content, None)
            .ok_or_else(|| FabricGuardError::Parse("Failed to parse Go code".to_string()))?;
        
        for pattern in &self.concurrency_patterns {
            let query = Query::new(tree_sitter_go::language(), &pattern.query)
                .map_err(|e| FabricGuardError::Parse(format!("Invalid query: {}", e)))?;
            
            let mut cursor = QueryCursor::new();
            let matches = cursor.matches(&query, tree.root_node(), content.as_bytes());
            
            for mat in matches {
                for capture in mat.captures {
                    let start = capture.node.start_position();
                    findings.push(Finding {
                        id: format!("SEC-CONC-{}", pattern.name.to_uppercase()),
                        severity: pattern.severity,
                        category: "security/concurrency".to_string(),
                        title: format!("Concurrency issue: {}", pattern.name),
                        description: pattern.description.clone(),
                        file: path.display().to_string(),
                        line: start.row + 1,
                        column: start.column,
                        code_snippet: Some(extract_code_snippet(content, start.row + 1, 3)),
                        remediation: Some("Ensure chaincode execution is deterministic".to_string()),
                        references: vec![],
                    });
                }
            }
        }
        
        // Check for ledger interaction issues
        for pattern in &self.ledger_patterns {
            for mat in pattern.regex.find_iter(content) {
                let line_number = content[..mat.start()].lines().count();
                findings.push(Finding {
                    id: format!("SEC-LED-{}", pattern.name.to_uppercase()),
                    severity: pattern.severity,
                    category: "security/ledger".to_string(),
                    title: format!("Ledger interaction issue: {}", pattern.name),
                    description: pattern.description.clone(),
                    file: path.display().to_string(),
                    line: line_number,
                    column: mat.start() - content.lines().take(line_number - 1).map(|l| l.len() + 1).sum::<usize>(),
                    code_snippet: Some(extract_code_snippet(content, line_number, 3)),
                    remediation: Some("Review ledger interaction patterns".to_string()),
                    references: vec![],
                });
            }
        }
        
        // Additional security checks
        findings.extend(self.check_crypto_issues(content, path)?);
        findings.extend(self.check_access_control(content, path)?);
        findings.extend(self.check_input_validation(content, path)?);
        
        Ok(findings)
    }

    pub fn quick_scan(&self, content: &str, path: &Path) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Only check for critical security issues in quick scan
        let critical_patterns = self.patterns.iter()
            .filter(|p| p.severity == Severity::Critical || p.severity == Severity::High);
        
        for pattern in critical_patterns {
            for mat in pattern.pattern.find_iter(content) {
                let line = content[..mat.start()].lines().count();
                let column = mat.start() - content[..mat.start()].rfind('\n').unwrap_or(0);
                
                findings.push(Finding {
                    id: pattern.id.clone(),
                    severity: pattern.severity,
                    category: "Security".to_string(),
                    title: pattern.title.clone(),
                    description: pattern.description.clone(),
                    file: path.to_string_lossy().to_string(),
                    line,
                    column,
                    code_snippet: Some(self.get_code_snippet(content, line)),
                    remediation: Some(pattern.remediation.clone()),
                    references: vec![],
                    confidence: 0.9,
                    ai_consensus: None,
                });
            }
        }
        
        Ok(findings)
    }
    
    fn check_crypto_issues(&self, content: &str, path: &Path) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for weak crypto algorithms
        let weak_crypto = vec![
            ("MD5", "MD5 is cryptographically broken"),
            ("SHA1", "SHA-1 is deprecated for security use"),
            ("DES", "DES encryption is too weak"),
            ("RC4", "RC4 has known vulnerabilities"),
        ];
        
        for (algo, desc) in weak_crypto {
            if content.contains(algo) {
                findings.push(Finding {
                    id: format!("SEC-CRYPTO-{}", algo),
                    severity: Severity::High,
                    category: "Security/Cryptography".to_string(),
                    title: format!("Weak cryptographic algorithm: {}", algo),
                    description: desc.to_string(),
                    file: path.to_string_lossy().to_string(),
                    line: 1,
                    column: 1,
                    code_snippet: None,
                    remediation: Some("Use strong cryptographic algorithms like SHA-256 or AES".to_string()),
                    references: vec!["https://owasp.org/www-project-cryptographic-storage-cheat-sheet/".to_string()],
                    confidence: 0.95,
                    ai_consensus: None,
                });
            }
        }
        
        Ok(findings)
    }
    
    fn check_access_control(&self, content: &str, path: &Path) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for missing access control
        let has_auth = content.contains("authenticate") || 
                      content.contains("authorize") ||
                      content.contains("GetCreator") ||
                      content.contains("checkAuth");
        
        if !has_auth && (content.contains("func ") || content.contains("function ")) {
            findings.push(Finding {
                id: "SEC-ACCESS-001".to_string(),
                severity: Severity::High,
                category: "Security/AccessControl".to_string(),
                title: "Missing access control implementation".to_string(),
                description: "No authentication or authorization checks found".to_string(),
                file: path.to_string_lossy().to_string(),
                line: 1,
                column: 1,
                code_snippet: None,
                remediation: Some("Implement proper authentication and authorization checks".to_string()),
                references: vec![],
                confidence: 0.7,
                ai_consensus: None,
            });
        }
        
        Ok(findings)
    }
    
    fn check_input_validation(&self, content: &str, path: &Path) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for input validation
        let has_validation = content.contains("validate") || 
                           content.contains("sanitize") ||
                           content.contains("check") ||
                           content.contains("verify");
        
        let has_user_input = content.contains("request") ||
                           content.contains("input") ||
                           content.contains("param") ||
                           content.contains("args");
        
        if has_user_input && !has_validation {
            findings.push(Finding {
                id: "SEC-INPUT-001".to_string(),
                severity: Severity::High,
                category: "Security/InputValidation".to_string(),
                title: "Missing input validation".to_string(),
                description: "User input is processed without validation".to_string(),
                file: path.to_string_lossy().to_string(),
                line: 1,
                column: 1,
                code_snippet: None,
                remediation: Some("Validate and sanitize all user inputs".to_string()),
                references: vec!["https://owasp.org/www-project-input-validation-cheat-sheet/".to_string()],
                confidence: 0.75,
                ai_consensus: None,
            });
        }
        
        Ok(findings)
    }
    
    fn get_code_snippet(&self, content: &str, line: usize) -> String {
        let lines: Vec<&str> = content.lines().collect();
        let start = if line > 2 { line - 2 } else { 1 };
        let end = std::cmp::min(line + 2, lines.len());
        
        lines[start - 1..end]
            .iter()
            .enumerate()
            .map(|(i, l)| format!("{:4} | {}", start + i, l))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn extract_code_snippet(content: &str, line: usize, context: usize) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let start = line.saturating_sub(context).max(1);
    let end = (line + context).min(lines.len());
    
    lines[start - 1..end]
        .iter()
        .enumerate()
        .map(|(i, line)| format!("{:4} | {}", start + i, line))
        .collect::<Vec<_>>()
        .join("\n")
} 