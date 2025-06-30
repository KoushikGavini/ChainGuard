use crate::{Finding, Result, Severity};
use regex::Regex;
use std::path::Path;

pub struct AIPatternValidator {
    hallucination_patterns: Vec<HallucinationPattern>,
    suspicious_patterns: Vec<SuspiciousPattern>,
}

#[derive(Debug)]
struct HallucinationPattern {
    name: String,
    regex: Regex,
    description: String,
}

#[derive(Debug)]
struct SuspiciousPattern {
    name: String,
    regex: Regex,
    severity: Severity,
    description: String,
}

impl AIPatternValidator {
    pub fn new() -> Self {
        let hallucination_patterns = vec![
            HallucinationPattern {
                name: "nonexistent_fabric_method".to_string(),
                regex: Regex::new(
                    r"stub\.(GetTransactionID|SetEvent|GetHistoryForKey|GetQueryResult)\s*\(",
                )
                .unwrap(),
                description: "Method name appears to be hallucinated or from wrong version"
                    .to_string(),
            },
            HallucinationPattern {
                name: "fabricated_import".to_string(),
                regex: Regex::new(
                    r#"import\s+["\(]github\.com/hyperledger/fabric-chaincode-go/pkg/\w+"#,
                )
                .unwrap(),
                description: "Import path structure doesn't match actual Fabric packages"
                    .to_string(),
            },
            HallucinationPattern {
                name: "invented_error_type".to_string(),
                regex: Regex::new(r"fabric\.(ChainCodeError|LedgerError|ValidationError)").unwrap(),
                description: "Error type doesn't exist in Fabric SDK".to_string(),
            },
            HallucinationPattern {
                name: "phantom_interface".to_string(),
                regex: Regex::new(r"implements\s+(SmartContract|ChainCode|Contract)Interface")
                    .unwrap(),
                description: "Interface name appears to be AI-generated".to_string(),
            },
        ];

        let suspicious_patterns = vec![
            SuspiciousPattern {
                name: "todo_placeholder".to_string(),
                regex: Regex::new(r"(?i)(todo|fixme|xxx|hack|placeholder|implement\s+later)")
                    .unwrap(),
                severity: Severity::Medium,
                description: "AI-generated placeholder code detected".to_string(),
            },
            SuspiciousPattern {
                name: "generic_error_handling".to_string(),
                regex: Regex::new(
                    r#"return\s+(nil|"",)?\s*(?:fmt\.Errorf|errors\.New)\s*\(\s*"error"\s*\)"#,
                )
                .unwrap(),
                severity: Severity::Low,
                description: "Generic error message typical of AI-generated code".to_string(),
            },
            SuspiciousPattern {
                name: "example_values".to_string(),
                regex: Regex::new(r#"(example|sample|test|demo|foo|bar|baz)\w*\s*[:=]"#).unwrap(),
                severity: Severity::Low,
                description: "Example variable names suggesting incomplete AI generation"
                    .to_string(),
            },
            SuspiciousPattern {
                name: "inconsistent_naming".to_string(),
                regex: Regex::new(r"(getUserData|get_user_data|GetUserdata)").unwrap(),
                severity: Severity::Low,
                description: "Inconsistent naming convention typical of AI mixing styles"
                    .to_string(),
            },
            SuspiciousPattern {
                name: "pseudo_implementation".to_string(),
                regex: Regex::new(
                    r"//\s*(?:Implementation|Logic|Code)\s+(?:goes|to\s+be\s+added)\s+here",
                )
                .unwrap(),
                severity: Severity::High,
                description: "Pseudo-implementation comment indicating incomplete AI generation"
                    .to_string(),
            },
            SuspiciousPattern {
                name: "hallucinated_annotation".to_string(),
                regex: Regex::new(r"@(?:ChainCode|SmartContract|Transactional|ReadOnly)\s*\(")
                    .unwrap(),
                severity: Severity::Medium,
                description: "Java-style annotation in Go code suggests AI confusion".to_string(),
            },
        ];

        Self {
            hallucination_patterns,
            suspicious_patterns,
        }
    }

    pub fn validate(&self, content: &str, path: &Path) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for hallucination patterns
        for pattern in &self.hallucination_patterns {
            for mat in pattern.regex.find_iter(content) {
                let line_number = content[..mat.start()].lines().count();
                findings.push(Finding {
                    id: format!("AI-HALL-{}", pattern.name.to_uppercase()),
                    severity: Severity::High,
                    category: "ai-validation/hallucination".to_string(),
                    title: format!("Potential AI hallucination: {}", pattern.name),
                    description: pattern.description.clone(),
                    file: path.display().to_string(),
                    line: line_number,
                    column: mat.start()
                        - content
                            .lines()
                            .take(line_number - 1)
                            .map(|l| l.len() + 1)
                            .sum::<usize>(),
                    code_snippet: Some(extract_snippet(content, line_number)),
                    remediation: Some(
                        "Verify this code element exists in the Fabric SDK documentation"
                            .to_string(),
                    ),
                    references: vec![
                        "https://hyperledger-fabric.readthedocs.io/en/latest/".to_string()
                    ],
                    ai_consensus: None,
                });
            }
        }

        // Check for suspicious AI patterns
        for pattern in &self.suspicious_patterns {
            for mat in pattern.regex.find_iter(content) {
                let line_number = content[..mat.start()].lines().count();
                findings.push(Finding {
                    id: format!("AI-SUSP-{}", pattern.name.to_uppercase()),
                    severity: pattern.severity,
                    category: "ai-validation/suspicious".to_string(),
                    title: format!("Suspicious AI pattern: {}", pattern.name),
                    description: pattern.description.clone(),
                    file: path.display().to_string(),
                    line: line_number,
                    column: mat.start()
                        - content
                            .lines()
                            .take(line_number - 1)
                            .map(|l| l.len() + 1)
                            .sum::<usize>(),
                    code_snippet: Some(extract_snippet(content, line_number)),
                    remediation: Some("Review and complete the implementation".to_string()),
                    references: vec![],
                    ai_consensus: None,
                });
            }
        }

        // Check for common AI code generation artifacts
        self.check_ai_artifacts(content, path, &mut findings);

        Ok(findings)
    }

    fn check_ai_artifacts(&self, content: &str, path: &Path, findings: &mut Vec<Finding>) {
        // Check for repeated patterns (common in AI generation)
        let lines: Vec<&str> = content.lines().collect();
        let mut pattern_count = std::collections::HashMap::new();

        for line in &lines {
            let trimmed = line.trim();
            if trimmed.len() > 20 {
                // Only check substantial lines
                *pattern_count.entry(trimmed).or_insert(0) += 1;
            }
        }

        for (pattern, count) in pattern_count {
            if count > 3 {
                findings.push(Finding {
                    id: "AI-ARTIFACT-REPETITION".to_string(),
                    severity: Severity::Medium,
                    category: "ai-validation/artifact".to_string(),
                    title: "Repeated code pattern detected".to_string(),
                    description: format!(
                        "Pattern repeated {} times, suggesting AI generation artifact",
                        count
                    ),
                    file: path.display().to_string(),
                    line: 0,
                    column: 0,
                    code_snippet: Some(pattern.to_string()),
                    remediation: Some(
                        "Review repeated patterns for necessary refactoring".to_string(),
                    ),
                    references: vec![],
                    ai_consensus: None,
                });
            }
        }

        // Check for unusually perfect formatting (AI tends to be too consistent)
        let mut perfect_indent_count = 0;
        for line in &lines {
            if line.starts_with("    ") || line.starts_with("\t") || line.is_empty() {
                perfect_indent_count += 1;
            }
        }

        if lines.len() > 50 && perfect_indent_count as f64 / lines.len() as f64 > 0.98 {
            findings.push(Finding {
                id: "AI-ARTIFACT-FORMATTING".to_string(),
                severity: Severity::Info,
                category: "ai-validation/artifact".to_string(),
                title: "Suspiciously perfect formatting".to_string(),
                description: "Code formatting is unusually consistent, may be AI-generated"
                    .to_string(),
                file: path.display().to_string(),
                line: 0,
                column: 0,
                code_snippet: None,
                remediation: Some("Ensure code has been properly reviewed by humans".to_string()),
                references: vec![],
                ai_consensus: None,
            });
        }
    }
}

fn extract_snippet(content: &str, line: usize) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let start = line.saturating_sub(2).max(1);
    let end = (line + 2).min(lines.len());

    lines[start - 1..end]
        .iter()
        .enumerate()
        .map(|(i, line)| format!("{:4} | {}", start + i, line))
        .collect::<Vec<_>>()
        .join("\n")
}
