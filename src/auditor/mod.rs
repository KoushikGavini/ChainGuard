use crate::{Result, ChainGuardError, Finding, Severity};
use serde::{Serialize, Deserialize};
use std::path::Path;
use std::collections::HashMap;

pub struct Auditor {
    compliance_rules: HashMap<String, ComplianceFramework>,
    fabric_compliance_enabled: bool,
    solana_compliance_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFramework {
    pub name: String,
    pub version: String,
    pub rules: Vec<ComplianceRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRule {
    pub id: String,
    pub category: String,
    pub description: String,
    pub severity: Severity,
    pub check_type: CheckType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CheckType {
    CodePattern(String),
    FunctionPresence(String),
    SecurityProperty(String),
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResult {
    pub compliance_score: f32,
    pub framework: String,
    pub findings: Vec<Finding>,
    pub passed_checks: usize,
    pub total_checks: usize,
}

impl Auditor {
    pub fn new() -> Self {
        Self {
            compliance_rules: HashMap::new(),
            fabric_compliance_enabled: false,
            solana_compliance_enabled: false,
        }
    }
    
    pub fn enable_fabric_compliance(&mut self) {
        self.fabric_compliance_enabled = true;
        self.load_fabric_compliance_rules();
    }
    
    pub fn enable_solana_compliance(&mut self) {
        self.solana_compliance_enabled = true;
        self.load_solana_compliance_rules();
    }
    
    pub fn load_framework(&mut self, framework_name: &str) -> Result<()> {
        let framework = match framework_name.to_lowercase().as_str() {
            "iso27001" => self.load_iso27001_framework(),
            "nist" => self.load_nist_framework(),
            "cis" => self.load_cis_framework(),
            "owasp" => self.load_owasp_framework(),
            _ => return Err(ChainGuardError::Config(
                format!("Unknown compliance framework: {}", framework_name)
            )),
        };
        
        self.compliance_rules.insert(framework_name.to_string(), framework);
        Ok(())
    }
    
    pub async fn audit(&self, path: &Path) -> Result<AuditResult> {
        let mut all_findings = Vec::new();
        let mut total_checks = 0;
        let mut passed_checks = 0;
        
        // Read the file or directory
        let files = self.collect_files(path).await?;
        
        // Run compliance checks
        for (_framework_name, framework) in &self.compliance_rules {
            for rule in &framework.rules {
                total_checks += 1;
                
                let violations = self.check_rule(&files, rule).await?;
                if violations.is_empty() {
                    passed_checks += 1;
                } else {
                    all_findings.extend(violations);
                }
            }
        }
        
        // Run Fabric-specific compliance if enabled
        if self.fabric_compliance_enabled {
            let fabric_findings = self.audit_fabric_compliance(&files).await?;
            all_findings.extend(fabric_findings);
        }
        
        let compliance_score = if total_checks > 0 {
            (passed_checks as f32 / total_checks as f32) * 100.0
        } else {
            100.0
        };
        
        Ok(AuditResult {
            compliance_score,
            framework: self.get_framework_names(),
            findings: all_findings,
            passed_checks,
            total_checks,
        })
    }
    
    async fn collect_files(&self, path: &Path) -> Result<Vec<(String, String)>> {
        let mut files = Vec::new();
        
        if path.is_file() {
            let content = tokio::fs::read_to_string(path).await?;
            files.push((path.to_string_lossy().to_string(), content));
        } else if path.is_dir() {
            let mut entries = tokio::fs::read_dir(path).await?;
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                if path.is_file() && self.should_audit_file(&path) {
                    let content = tokio::fs::read_to_string(&path).await?;
                    files.push((path.to_string_lossy().to_string(), content));
                }
            }
        }
        
        Ok(files)
    }
    
    async fn check_rule(
        &self,
        files: &[(String, String)],
        rule: &ComplianceRule,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        for (file_path, content) in files {
            match &rule.check_type {
                CheckType::CodePattern(pattern) => {
                    if let Some(violation) = self.check_code_pattern(content, pattern, rule) {
                        findings.push(self.create_finding(file_path, rule, violation));
                    }
                }
                CheckType::FunctionPresence(function) => {
                    if !self.check_function_presence(content, function) {
                        findings.push(self.create_finding(
                            file_path,
                            rule,
                            format!("Required function '{}' not found", function)
                        ));
                    }
                }
                CheckType::SecurityProperty(property) => {
                    if let Some(violation) = self.check_security_property(content, property, rule) {
                        findings.push(self.create_finding(file_path, rule, violation));
                    }
                }
                CheckType::Custom(check_name) => {
                    if let Some(violation) = self.run_custom_check(content, check_name, rule) {
                        findings.push(self.create_finding(file_path, rule, violation));
                    }
                }
            }
        }
        
        Ok(findings)
    }
    
    fn check_code_pattern(
        &self,
        content: &str,
        pattern: &str,
        _rule: &ComplianceRule,
    ) -> Option<String> {
        use regex::Regex;
        
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(content) {
                return Some(format!("Code pattern '{}' found", pattern));
            }
        }
        None
    }
    
    fn check_function_presence(&self, content: &str, function: &str) -> bool {
        content.contains(&format!("func {}", function)) ||
        content.contains(&format!("function {}", function)) ||
        content.contains(&format!("def {}", function))
    }
    
    fn check_security_property(
        &self,
        content: &str,
        property: &str,
        _rule: &ComplianceRule,
    ) -> Option<String> {
        match property {
            "no_hardcoded_secrets" => {
                if content.contains("password =") || content.contains("secret =") {
                    return Some("Hardcoded secrets detected".to_string());
                }
            }
            "input_validation" => {
                if !content.contains("validate") && !content.contains("sanitize") {
                    return Some("Input validation not implemented".to_string());
                }
            }
            "encryption_at_rest" => {
                if !content.contains("encrypt") && !content.contains("crypto") {
                    return Some("Encryption at rest not implemented".to_string());
                }
            }
            _ => {}
        }
        None
    }
    
    fn run_custom_check(
        &self,
        _content: &str,
        _check_name: &str,
        _rule: &ComplianceRule,
    ) -> Option<String> {
        // Custom checks would be implemented here
        None
    }
    
    async fn audit_fabric_compliance(&self, files: &[(String, String)]) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        for (file_path, content) in files {
            // Check Fabric best practices
            if !content.contains("GetCreator") {
                findings.push(Finding {
                    id: "FABRIC-COMP-001".to_string(),
                    severity: Severity::Medium,
                    category: "Compliance/Fabric".to_string(),
                    title: "Missing transaction creator validation".to_string(),
                    description: "Chaincode does not validate transaction creator".to_string(),
                    file: file_path.clone(),
                    line: 1,
                    column: 1,
                    code_snippet: None,
                    remediation: Some("Implement GetCreator() validation".to_string()),
                    references: vec![],
                    ai_consensus: None
                });
            }
            
            if content.contains("time.Now()") {
                findings.push(Finding {
                    id: "FABRIC-COMP-002".to_string(),
                    severity: Severity::High,
                    category: "Compliance/Fabric".to_string(),
                    title: "Non-deterministic time usage".to_string(),
                    description: "Using time.Now() violates Fabric determinism requirements".to_string(),
                    file: file_path.clone(),
                    line: 1,
                    column: 1,
                    code_snippet: None,
                    remediation: Some("Use GetTxTimestamp() instead".to_string()),
                    references: vec![],
                    ai_consensus: None
                });
            }
        }
        
        Ok(findings)
    }
    
    fn create_finding(
        &self,
        file_path: &str,
        rule: &ComplianceRule,
        violation: String,
    ) -> Finding {
        Finding {
            id: rule.id.clone(),
            severity: rule.severity,
            category: format!("Compliance/{}", rule.category),
            title: rule.description.clone(),
            description: violation,
            file: file_path.to_string(),
            line: 1,
            column: 1,
            code_snippet: None,
            remediation: None,
            references: vec![],
            ai_consensus: None,
        }
    }
    
    fn should_audit_file(&self, path: &Path) -> bool {
        matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("go") | Some("js") | Some("ts") | Some("sol") | Some("yaml") | Some("json")
        )
    }
    
    fn get_framework_names(&self) -> String {
        self.compliance_rules.keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    }
    
    fn load_fabric_compliance_rules(&mut self) {
        let framework = ComplianceFramework {
            name: "Hyperledger Fabric Best Practices".to_string(),
            version: "2.5".to_string(),
            rules: vec![
                ComplianceRule {
                    id: "FABRIC-BP-001".to_string(),
                    category: "Security".to_string(),
                    description: "Validate transaction creator".to_string(),
                    severity: Severity::High,
                    check_type: CheckType::FunctionPresence("GetCreator".to_string()),
                },
                ComplianceRule {
                    id: "FABRIC-BP-002".to_string(),
                    category: "Determinism".to_string(),
                    description: "Avoid non-deterministic operations".to_string(),
                    severity: Severity::Critical,
                    check_type: CheckType::CodePattern(r"time\.Now\(\)|rand\.|map\s+range".to_string()),
                },
            ],
        };
        
        self.compliance_rules.insert("fabric".to_string(), framework);
    }
    
    fn load_solana_compliance_rules(&mut self) {
        let framework = ComplianceFramework {
            name: "Solana Best Practices".to_string(),
            version: "1.0".to_string(),
            rules: vec![
                ComplianceRule {
                    id: "SOL-BP-001".to_string(),
                    category: "Security".to_string(),
                    description: "Validate account ownership".to_string(),
                    severity: Severity::Critical,
                    check_type: CheckType::CodePattern(r"owner\s*==".to_string()),
                },
                ComplianceRule {
                    id: "SOL-BP-002".to_string(),
                    category: "Security".to_string(),
                    description: "Check signer status".to_string(),
                    severity: Severity::Critical,
                    check_type: CheckType::CodePattern(r"is_signer".to_string()),
                },
                ComplianceRule {
                    id: "SOL-BP-003".to_string(),
                    category: "Arithmetic".to_string(),
                    description: "Use checked arithmetic".to_string(),
                    severity: Severity::High,
                    check_type: CheckType::CodePattern(r"checked_add|checked_sub|checked_mul".to_string()),
                },
            ],
        };
        
        self.compliance_rules.insert("solana".to_string(), framework);
    }
    
    fn load_iso27001_framework(&self) -> ComplianceFramework {
        ComplianceFramework {
            name: "ISO 27001".to_string(),
            version: "2022".to_string(),
            rules: vec![
                ComplianceRule {
                    id: "ISO27001-A.8.24".to_string(),
                    category: "Cryptography".to_string(),
                    description: "Use of cryptography".to_string(),
                    severity: Severity::High,
                    check_type: CheckType::SecurityProperty("encryption_at_rest".to_string()),
                },
            ],
        }
    }
    
    fn load_nist_framework(&self) -> ComplianceFramework {
        ComplianceFramework {
            name: "NIST Cybersecurity Framework".to_string(),
            version: "1.1".to_string(),
            rules: vec![
                ComplianceRule {
                    id: "NIST-PR.DS-1".to_string(),
                    category: "Data Security".to_string(),
                    description: "Data-at-rest protection".to_string(),
                    severity: Severity::High,
                    check_type: CheckType::SecurityProperty("encryption_at_rest".to_string()),
                },
            ],
        }
    }
    
    fn load_cis_framework(&self) -> ComplianceFramework {
        ComplianceFramework {
            name: "CIS Controls".to_string(),
            version: "8".to_string(),
            rules: vec![
                ComplianceRule {
                    id: "CIS-3.3".to_string(),
                    category: "Data Protection".to_string(),
                    description: "Configure Data Access Control".to_string(),
                    severity: Severity::High,
                    check_type: CheckType::FunctionPresence("AccessControl".to_string()),
                },
            ],
        }
    }
    
    fn load_owasp_framework(&self) -> ComplianceFramework {
        ComplianceFramework {
            name: "OWASP Top 10".to_string(),
            version: "2021".to_string(),
            rules: vec![
                ComplianceRule {
                    id: "OWASP-A03".to_string(),
                    category: "Injection".to_string(),
                    description: "Input validation required".to_string(),
                    severity: Severity::Critical,
                    check_type: CheckType::SecurityProperty("input_validation".to_string()),
                },
            ],
        }
    }
} 