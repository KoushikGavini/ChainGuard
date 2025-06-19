use crate::{Finding, Result, Severity};
use regex::Regex;
use std::path::Path;
use lazy_static::lazy_static;

pub struct PerformanceAnalyzer {
    query_patterns: Vec<QueryPattern>,
    inefficiency_patterns: Vec<InefficiencyPattern>,
}

#[derive(Debug)]
struct QueryPattern {
    name: String,
    regex: Regex,
    severity: Severity,
    description: String,
    optimization: String,
}

#[derive(Debug)]
struct InefficiencyPattern {
    name: String,
    regex: Regex,
    severity: Severity,
    description: String,
}

lazy_static! {
    static ref UNBOUNDED_QUERY: Regex = Regex::new(r"GetQueryResult[^}]+").unwrap();
    static ref NESTED_LOOP: Regex = Regex::new(r"for\s+.*\s+in\s+.*\s*\{\s*for\s+.*\s+in\s+").unwrap();
    static ref LARGE_ARRAY: Regex = Regex::new(r"make\s*\(\s*\[\s*\]\s*\w+\s*,\s*(\d{4,})\s*\)").unwrap();
    static ref STRING_CONCAT: Regex = Regex::new(r#"(\w+)\s*=\s*\1\s*\+\s*"#).unwrap();
}

impl PerformanceAnalyzer {
    pub fn new() -> Self {
        let query_patterns = vec![
            QueryPattern {
                name: "unbounded_range_query".to_string(),
                regex: Regex::new(r#"GetStateByRange\s*\(\s*""\s*,\s*""\s*\)"#).unwrap(),
                severity: Severity::High,
                description: "Unbounded range query can cause performance issues".to_string(),
                optimization: "Use pagination with limited range queries".to_string(),
            },

            QueryPattern {
                name: "inefficient_composite_key".to_string(),
                regex: Regex::new(r"CreateCompositeKey\s*\([^,]+,\s*\[\s*\]\s*\)").unwrap(),
                severity: Severity::Low,
                description: "Empty attributes in composite key reduce query efficiency".to_string(),
                optimization: "Add meaningful attributes to composite keys".to_string(),
            },
        ];
        
        let inefficiency_patterns = vec![
            InefficiencyPattern {
                name: "multiple_getstate".to_string(),
                regex: Regex::new(r"(GetState\s*\([^)]+\)[^{]*){3,}").unwrap(),
                severity: Severity::Medium,
                description: "Multiple sequential GetState calls can be optimized".to_string(),
            },
            InefficiencyPattern {
                name: "json_in_loop".to_string(),
                regex: Regex::new(r"for\s+.*\{[^}]*json\.(Marshal|Unmarshal)").unwrap(),
                severity: Severity::Medium,
                description: "JSON operations in loops are computationally expensive".to_string(),
            },
            InefficiencyPattern {
                name: "large_payload_storage".to_string(),
                regex: Regex::new(r"PutState\s*\([^,]+,\s*[^)]*\[\d{5,}\]byte").unwrap(),
                severity: Severity::High,
                description: "Storing large payloads impacts network and storage performance".to_string(),
            },
            InefficiencyPattern {
                name: "synchronous_external_call".to_string(),
                regex: Regex::new(r"(http\.|net\.Dial|rpc\.)").unwrap(),
                severity: Severity::Critical,
                description: "Synchronous external calls block transaction processing".to_string(),
            },
        ];
        
        Self {
            query_patterns,
            inefficiency_patterns,
        }
    }

    pub fn analyze(&self, content: &str, path: &Path) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check query patterns
        for pattern in &self.query_patterns {
            for mat in pattern.regex.find_iter(content) {
                let line_number = content[..mat.start()].lines().count();
                findings.push(Finding {
                    id: format!("PERF-QUERY-{}", pattern.name.to_uppercase()),
                    severity: pattern.severity,
                    category: "performance/query".to_string(),
                    title: format!("Query performance issue: {}", pattern.name),
                    description: pattern.description.clone(),
                    file: path.display().to_string(),
                    line: line_number,
                    column: mat.start() - content.lines().take(line_number - 1).map(|l| l.len() + 1).sum::<usize>(),
                    code_snippet: Some(extract_snippet(content, line_number)),
                    remediation: Some(pattern.optimization.clone()),
                    references: vec![
                        "https://hyperledger-fabric.readthedocs.io/en/latest/couchdb_as_state_database.html".to_string()
                    ],
                    ai_consensus: None,
                });
            }
        }
        
        // Check inefficiency patterns
        for pattern in &self.inefficiency_patterns {
            for mat in pattern.regex.find_iter(content) {
                let line_number = content[..mat.start()].lines().count();
                findings.push(Finding {
                    id: format!("PERF-INEFF-{}", pattern.name.to_uppercase()),
                    severity: pattern.severity,
                    category: "performance/efficiency".to_string(),
                    title: format!("Performance inefficiency: {}", pattern.name),
                    description: pattern.description.clone(),
                    file: path.display().to_string(),
                    line: line_number,
                    column: mat.start() - content.lines().take(line_number - 1).map(|l| l.len() + 1).sum::<usize>(),
                    code_snippet: Some(extract_snippet(content, line_number)),
                    remediation: Some("Optimize code for better performance".to_string()),
                    references: vec![],
                    ai_consensus: None,
                });
            }
        }
        
        // Check for endorsement policy inefficiencies
        self.check_endorsement_patterns(content, path, &mut findings);
        
        // Check for unbounded queries (missing pagination)
        if UNBOUNDED_QUERY.is_match(content) && !content.contains("pageSize") && !content.contains("bookmark") {
            findings.push(Finding {
                id: "PERF-QUERY-UNBOUNDED".to_string(),
                severity: Severity::High,
                category: "performance/query".to_string(),
                title: "Unbounded query detected".to_string(),
                description: "Query lacks pagination parameters which can cause performance issues with large datasets".to_string(),
                file: path.display().to_string(),
                line: 0,
                column: 0,
                code_snippet: None,
                remediation: Some("Add pageSize and bookmark parameters for pagination".to_string()),
                references: vec![],
                ai_consensus: None,
            });
        }
        
        Ok(findings)
    }
    
    fn check_endorsement_patterns(&self, content: &str, path: &Path, findings: &mut Vec<Finding>) {
        // Check for overly complex endorsement logic
        let complex_endorsement = Regex::new(r"(GetMSPID|GetCreator)\s*\([^{]*\{[^}]{200,}").unwrap();
        for mat in complex_endorsement.find_iter(content) {
            let line_number = content[..mat.start()].lines().count();
            findings.push(Finding {
                id: "PERF-ENDORSEMENT-COMPLEX".to_string(),
                severity: Severity::Medium,
                category: "performance/endorsement".to_string(),
                title: "Complex endorsement validation logic".to_string(),
                description: "Complex endorsement checks impact transaction performance".to_string(),
                file: path.display().to_string(),
                line: line_number,
                column: 0,
                code_snippet: Some(extract_snippet(content, line_number)),
                remediation: Some("Consider using chaincode-level endorsement policies".to_string()),
                references: vec![],
                    ai_consensus: None
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