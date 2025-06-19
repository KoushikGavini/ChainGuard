use crate::{Result, ChainGuardError, Finding, Severity};
use serde::{Serialize, Deserialize};
use std::path::Path;
use tree_sitter::{Parser, Query, QueryCursor};
use regex::Regex;

pub mod determinism;
pub mod endorsement;
pub mod state_db;
pub mod private_data;
pub mod performance;

pub struct FabricAnalyzer {
    parser: Parser,
    determinism_analyzer: determinism::DeterminismAnalyzer,
    endorsement_analyzer: endorsement::EndorsementAnalyzer,
    state_db_analyzer: state_db::StateDBAnalyzer,
    private_data_analyzer: private_data::PrivateDataAnalyzer,
    performance_analyzer: performance::FabricPerformanceAnalyzer,
}

impl FabricAnalyzer {
    pub fn new() -> Result<Self> {
        let mut parser = Parser::new();
        parser.set_language(tree_sitter_go::language())
            .map_err(|e| ChainGuardError::Parse(format!("Failed to set Go language: {}", e)))?;
        
        Ok(Self {
            parser,
            determinism_analyzer: determinism::DeterminismAnalyzer::new(),
            endorsement_analyzer: endorsement::EndorsementAnalyzer::new(),
            state_db_analyzer: state_db::StateDBAnalyzer::new(),
            private_data_analyzer: private_data::PrivateDataAnalyzer::new(),
            performance_analyzer: performance::FabricPerformanceAnalyzer::new(),
        })
    }
    
    pub async fn analyze_chaincode(&mut self, path: &Path) -> Result<FabricAnalysisResult> {
        let content = tokio::fs::read_to_string(path).await?;
        let mut findings = Vec::new();
        
        // Parse the chaincode
        let tree = self.parser.parse(&content, None)
            .ok_or_else(|| ChainGuardError::Parse("Failed to parse chaincode".to_string()))?;
        
        // Run all Fabric-specific analyses
        findings.extend(self.check_nondeterminism(&content, &tree)?);
        findings.extend(self.check_global_variables(&content, &tree)?);
        findings.extend(self.check_rich_queries(&content, &tree)?);
        findings.extend(self.check_endorsement_policy(&content, &tree)?);
        findings.extend(self.check_private_data_security(&content, &tree)?);
        findings.extend(self.check_mvcc_compliance(&content, &tree)?);
        findings.extend(self.check_dos_vulnerabilities(&content, &tree)?);
        findings.extend(self.check_channel_isolation(&content, &tree)?);
        
        // Run determinism analysis
        let determinism_issues = self.determinism_analyzer.analyze(&content, &tree)?;
        findings.extend(determinism_issues);
        
        // Run endorsement policy analysis
        let endorsement_issues = self.endorsement_analyzer.analyze(&content, &tree)?;
        findings.extend(endorsement_issues);
        
        // Run state database analysis
        let state_db_issues = self.state_db_analyzer.analyze(&content, &tree)?;
        findings.extend(state_db_issues);
        
        // Run private data analysis
        let private_data_issues = self.private_data_analyzer.analyze(&content, &tree)?;
        findings.extend(private_data_issues);
        
        // Run performance analysis
        let performance_issues = self.performance_analyzer.analyze(&content, &tree)?;
        findings.extend(performance_issues);
        
        Ok(FabricAnalysisResult {
            findings: findings.clone(),
            determinism_score: self.calculate_determinism_score(&findings),
            security_score: self.calculate_security_score(&findings),
            performance_score: self.calculate_performance_score(&findings),
            fabric_best_practices_score: self.calculate_best_practices_score(&findings),
            optimization_suggestions: Vec::new(),
        })
    }
    
    fn check_nondeterminism(&self, content: &str, tree: &tree_sitter::Tree) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for time-based operations
        let time_patterns = vec![
            r"time\.Now\(\)",
            r"time\.Unix\(",
            r"rand\.",
            r"math/rand",
        ];
        
        for pattern in time_patterns {
            let regex = Regex::new(pattern).unwrap();
            for mat in regex.find_iter(content) {
                let pos = mat.start();
                let (line, column) = self.get_line_column(content, pos);
                
                findings.push(Finding {
                    id: format!("FABRIC-ND-001"),
                    severity: Severity::Critical,
                    category: "Fabric/Nondeterminism".to_string(),
                    title: "Nondeterministic operation detected".to_string(),
                    description: format!(
                        "Use of {} can lead to nondeterministic behavior in chaincode. \
                        Different peers may produce different results, causing consensus failure.",
                        pattern
                    ),
                    file: "".to_string(),
                    line,
                    column,
                    code_snippet: Some(self.get_code_snippet(content, line)),
                    remediation: Some(
                        "Use deterministic alternatives like block timestamp or transaction ID".to_string()
                    ),
                    references: vec![
                        "https://hyperledger-fabric.readthedocs.io/en/latest/chaincode4ade.html#chaincode-determinism".to_string()
                    ],
                    ai_consensus: None,
                });
            }
        }
        
        Ok(findings)
    }
    
    fn check_global_variables(&self, content: &str, tree: &tree_sitter::Tree) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Query for global variable declarations
        let query_str = r#"
        (source_file
          (var_declaration
            (var_spec
              name: (identifier) @var_name
              type: (_)? @var_type
              value: (_)? @var_value)))
        "#;
        
        let query = Query::new(tree_sitter_go::language(), query_str)
            .map_err(|e| ChainGuardError::Parse(format!("Failed to create query: {}", e)))?;
        
        let mut cursor = QueryCursor::new();
        let matches = cursor.matches(&query, tree.root_node(), content.as_bytes());
        
        for match_ in matches {
            for capture in match_.captures {
                let node = capture.node;
                let text = node.utf8_text(content.as_bytes()).unwrap();
                
                // Check if it's a mutable global variable
                if !text.starts_with("const") {
                    let start = node.start_position();
                    
                    findings.push(Finding {
                        id: "FABRIC-GV-001".to_string(),
                        severity: Severity::High,
                        category: "Fabric/GlobalVariables".to_string(),
                        title: "Global variable detected in chaincode".to_string(),
                        description: format!(
                            "Global variable '{}' can cause nondeterministic behavior. \
                            State should be managed through the ledger, not in-memory variables.",
                            text
                        ),
                        file: "".to_string(),
                        line: start.row + 1,
                        column: start.column + 1,
                        code_snippet: Some(self.get_code_snippet(content, start.row + 1)),
                        remediation: Some(
                            "Store state in the ledger using stub.PutState() instead of global variables".to_string()
                        ),
                        references: vec![],
                        ai_consensus: None,
                    });
                }
            }
        }
        
        Ok(findings)
    }
    
    fn check_rich_queries(&self, content: &str, tree: &tree_sitter::Tree) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for CouchDB rich queries
        let rich_query_patterns = vec![
            r"GetQueryResult\s*\(",
            r"GetQueryResultWithPagination\s*\(",
            r"GetPrivateDataQueryResult\s*\(",
        ];
        
        for pattern in rich_query_patterns {
            let regex = Regex::new(pattern).unwrap();
            for mat in regex.find_iter(content) {
                let pos = mat.start();
                let (line, column) = self.get_line_column(content, pos);
                
                findings.push(Finding {
                    id: "FABRIC-RQ-001".to_string(),
                    severity: Severity::Medium,
                    category: "Fabric/RichQueries".to_string(),
                    title: "Rich query usage detected".to_string(),
                    description: 
                        "Rich queries are not guaranteed to be re-executed during validation phase. \
                        This can lead to phantom reads and non-deterministic behavior.".to_string(),
                    file: "".to_string(),
                    line,
                    column,
                    code_snippet: Some(self.get_code_snippet(content, line)),
                    remediation: Some(
                        "Consider using composite keys with range queries for deterministic behavior".to_string()
                    ),
                    references: vec![
                        "https://hyperledger-fabric.readthedocs.io/en/latest/couchdb_as_state_database.html".to_string()
                    ],
                    ai_consensus: None
                });
            }
        }
        
        Ok(findings)
    }
    
    fn check_endorsement_policy(&self, content: &str, tree: &tree_sitter::Tree) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for proper endorsement policy validation
        let has_creator_check = content.contains("GetCreator()");
        let has_msp_id_check = content.contains("GetMSPID()");
        
        if !has_creator_check && !has_msp_id_check {
            findings.push(Finding {
                id: "FABRIC-EP-001".to_string(),
                severity: Severity::High,
                category: "Fabric/EndorsementPolicy".to_string(),
                title: "Missing endorsement policy validation".to_string(),
                description: 
                    "Chaincode does not validate transaction creator or MSP ID. \
                    This could allow unauthorized organizations to invoke transactions.".to_string(),
                file: "".to_string(),
                line: 1,
                column: 1,
                code_snippet: None,
                remediation: Some(
                    "Implement proper access control using stub.GetCreator() and validate MSP IDs".to_string()
                ),
                references: vec![],
                ai_consensus: None
                });
        }
        
        Ok(findings)
    }
    
    fn check_private_data_security(&self, content: &str, tree: &tree_sitter::Tree) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for private data leakage
        let private_data_patterns = vec![
            (r"GetPrivateData\s*\(", r"PutState\s*\("),
            (r"GetPrivateDataByRange\s*\(", r"PutState\s*\("),
        ];
        
        for (get_pattern, put_pattern) in private_data_patterns {
            let get_regex = Regex::new(get_pattern).unwrap();
            let put_regex = Regex::new(put_pattern).unwrap();
            
            // Simple heuristic: if we see GetPrivateData followed by PutState in nearby lines
            for get_match in get_regex.find_iter(content) {
                let get_pos = get_match.start();
                let (get_line, _) = self.get_line_column(content, get_pos);
                
                // Check next 10 lines for PutState
                let lines: Vec<&str> = content.lines().collect();
                for i in get_line..std::cmp::min(get_line + 10, lines.len()) {
                    if put_regex.is_match(lines[i - 1]) {
                        findings.push(Finding {
                            id: "FABRIC-PD-001".to_string(),
                            severity: Severity::Critical,
                            category: "Fabric/PrivateData".to_string(),
                            title: "Potential private data leakage".to_string(),
                            description: 
                                "Private data appears to be written to public state. \
                                This could expose confidential information to all channel members.".to_string(),
                            file: "".to_string(),
                            line: get_line,
                            column: 1,
                            code_snippet: Some(self.get_code_snippet(content, get_line)),
                            remediation: Some(
                                "Use PutPrivateData() to store private data, not PutState()".to_string()
                            ),
                            references: vec![],
                            ai_consensus: None
                });
                        break;
                    }
                }
            }
        }
        
        Ok(findings)
    }
    
    fn check_mvcc_compliance(&self, content: &str, tree: &tree_sitter::Tree) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for MVCC read conflicts
        let read_patterns = vec![
            r"GetState\s*\(",
            r"GetStateByRange\s*\(",
        ];
        
        // Simple check: multiple reads of same key without proper handling
        for pattern in read_patterns {
            let regex = Regex::new(pattern).unwrap();
            let matches: Vec<_> = regex.find_iter(content).collect();
            
            if matches.len() > 2 {
                findings.push(Finding {
                    id: "FABRIC-MVCC-001".to_string(),
                    severity: Severity::Medium,
                    category: "Fabric/MVCC".to_string(),
                    title: "Potential MVCC read conflict".to_string(),
                    description: 
                        "Multiple state reads detected. Concurrent transactions may cause MVCC conflicts \
                        if the same keys are modified.".to_string(),
                    file: "".to_string(),
                    line: 1,
                    column: 1,
                    code_snippet: None,
                    remediation: Some(
                        "Minimize the number of GetState calls and consider transaction ordering".to_string()
                    ),
                    references: vec![],
                    ai_consensus: None
                });
            }
        }
        
        Ok(findings)
    }
    
    fn check_dos_vulnerabilities(&self, content: &str, tree: &tree_sitter::Tree) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for unbounded loops
        let loop_patterns = vec![
            r"for\s+range\s+",
            r"for\s*\{",
            r"for\s+.*;.*;.*\{",
        ];
        
        for pattern in loop_patterns {
            let regex = Regex::new(pattern).unwrap();
            for mat in regex.find_iter(content) {
                let pos = mat.start();
                let (line, column) = self.get_line_column(content, pos);
                
                // Check if the loop has a reasonable bound
                let loop_context = self.get_context_around(content, pos, 200);
                if !loop_context.contains("break") && !loop_context.contains("return") {
                    findings.push(Finding {
                        id: "FABRIC-DOS-001".to_string(),
                        severity: Severity::High,
                        category: "Fabric/DoS".to_string(),
                        title: "Potential DoS vulnerability - unbounded loop".to_string(),
                        description: 
                            "Unbounded loop detected. This could be exploited to consume excessive \
                            resources and cause denial of service.".to_string(),
                        file: "".to_string(),
                        line,
                        column,
                        code_snippet: Some(self.get_code_snippet(content, line)),
                        remediation: Some(
                            "Add explicit bounds checking and limits to all loops".to_string()
                        ),
                        references: vec![],
                        ai_consensus: None
                });
                }
            }
        }
        
        // Check for large data operations
        let large_data_patterns = vec![
            r"GetStateByRange\s*\([^)]*\)",
            r"GetHistoryForKey\s*\(",
        ];
        
        for pattern in large_data_patterns {
            let regex = Regex::new(pattern).unwrap();
            for mat in regex.find_iter(content) {
                let pos = mat.start();
                let (line, column) = self.get_line_column(content, pos);
                
                findings.push(Finding {
                    id: "FABRIC-DOS-002".to_string(),
                    severity: Severity::Medium,
                    category: "Fabric/DoS".to_string(),
                    title: "Potential DoS - unbounded data retrieval".to_string(),
                    description: 
                        "Unbounded state query detected. Large result sets could cause memory exhaustion.".to_string(),
                    file: "".to_string(),
                    line,
                    column,
                    code_snippet: Some(self.get_code_snippet(content, line)),
                    remediation: Some(
                        "Use pagination with GetStateByRangeWithPagination() to limit result size".to_string()
                    ),
                    references: vec![],
                    ai_consensus: None
                });
            }
        }
        
        Ok(findings)
    }
    
    fn check_channel_isolation(&self, content: &str, tree: &tree_sitter::Tree) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for cross-channel data access attempts
        let channel_patterns = vec![
            r"GetChannelID\s*\(",
            r"channel\s*:=",
        ];
        
        let mut has_channel_check = false;
        for pattern in channel_patterns {
            if Regex::new(pattern).unwrap().is_match(content) {
                has_channel_check = true;
                break;
            }
        }
        
        if has_channel_check {
            findings.push(Finding {
                id: "FABRIC-CH-001".to_string(),
                severity: Severity::Low,
                category: "Fabric/ChannelIsolation".to_string(),
                title: "Channel ID usage detected".to_string(),
                description: 
                    "Chaincode is channel-aware. Ensure proper isolation between channels \
                    and no cross-channel data leakage.".to_string(),
                file: "".to_string(),
                line: 1,
                column: 1,
                code_snippet: None,
                remediation: Some(
                    "Verify that channel-specific data is properly isolated".to_string()
                ),
                references: vec![],
                ai_consensus: None
                });
        }
        
        Ok(findings)
    }
    
    // Helper methods
    fn get_line_column(&self, content: &str, pos: usize) -> (usize, usize) {
        let mut line = 1;
        let mut column = 1;
        
        for (i, ch) in content.chars().enumerate() {
            if i == pos {
                break;
            }
            if ch == '\n' {
                line += 1;
                column = 1;
            } else {
                column += 1;
            }
        }
        
        (line, column)
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
    
    fn get_context_around(&self, content: &str, pos: usize, context_size: usize) -> String {
        let start = if pos > context_size { pos - context_size } else { 0 };
        let end = std::cmp::min(pos + context_size, content.len());
        content[start..end].to_string()
    }
    
    fn calculate_determinism_score(&self, findings: &[Finding]) -> f32 {
        let determinism_findings = findings.iter()
            .filter(|f| f.category.contains("Determinism") || f.category.contains("Nondeterminism"))
            .count();
        
        100.0 - (determinism_findings as f32 * 10.0).min(100.0)
    }
    
    fn calculate_security_score(&self, findings: &[Finding]) -> f32 {
        let security_weight = |severity: &Severity| match severity {
            Severity::Critical => 20.0,
            Severity::High => 10.0,
            Severity::Medium => 5.0,
            Severity::Low => 2.0,
            Severity::Info => 0.0,
        };
        
        let total_weight: f32 = findings.iter()
            .filter(|f| f.category.contains("Security") || f.category.contains("PrivateData"))
            .map(|f| security_weight(&f.severity))
            .sum();
        
        100.0 - total_weight.min(100.0)
    }
    
    fn calculate_performance_score(&self, findings: &[Finding]) -> f32 {
        let perf_findings = findings.iter()
            .filter(|f| f.category.contains("Performance") || f.category.contains("DoS"))
            .count();
        
        100.0 - (perf_findings as f32 * 15.0).min(100.0)
    }
    
    fn calculate_best_practices_score(&self, findings: &[Finding]) -> f32 {
        let total_findings = findings.len() as f32;
        100.0 - (total_findings * 2.0).min(100.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FabricAnalysisResult {
    pub findings: Vec<Finding>,
    pub determinism_score: f32,
    pub security_score: f32,
    pub performance_score: f32,
    pub fabric_best_practices_score: f32,
    pub optimization_suggestions: Vec<String>,
} 