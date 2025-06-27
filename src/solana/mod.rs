use crate::{Result, ChainGuardError, Finding, Severity};
use serde::{Serialize, Deserialize};
use std::path::Path;
use tree_sitter::Parser;
use regex::Regex;

pub mod account_validation;
pub mod cpi_security;
pub mod signer_checks;
pub mod ownership_validation;
pub mod arithmetic_checks;
pub mod performance;

pub struct SolanaAnalyzer {
    parser: Parser,
    account_validator: account_validation::AccountValidator,
    cpi_analyzer: cpi_security::CPIAnalyzer,
    signer_analyzer: signer_checks::SignerAnalyzer,
    ownership_analyzer: ownership_validation::OwnershipAnalyzer,
    arithmetic_analyzer: arithmetic_checks::ArithmeticAnalyzer,
    performance_analyzer: performance::SolanaPerformanceAnalyzer,
}

impl SolanaAnalyzer {
    pub fn new() -> Result<Self> {
        let mut parser = Parser::new();
        // TODO: Fix tree-sitter version conflicts - temporarily disabled
        // parser.set_language(tree_sitter_rust::language())
        //     .map_err(|e| ChainGuardError::Parse(format!("Failed to set Rust language: {}", e)))?;
        
        Ok(Self {
            parser,
            account_validator: account_validation::AccountValidator::new(),
            cpi_analyzer: cpi_security::CPIAnalyzer::new(),
            signer_analyzer: signer_checks::SignerAnalyzer::new(),
            ownership_analyzer: ownership_validation::OwnershipAnalyzer::new(),
            arithmetic_analyzer: arithmetic_checks::ArithmeticAnalyzer::new(),
            performance_analyzer: performance::SolanaPerformanceAnalyzer::new(),
        })
    }
    
    pub async fn analyze_program(&mut self, path: &Path) -> Result<SolanaAnalysisResult> {
        let content = tokio::fs::read_to_string(path).await?;
        let mut findings = Vec::new();
        
        // Parse the program
        let tree = self.parser.parse(&content, None)
            .ok_or_else(|| ChainGuardError::Parse("Failed to parse Solana program".to_string()))?;
        
        // Run all Solana-specific analyses
        findings.extend(self.check_account_validation(&content, &tree)?);
        findings.extend(self.check_signer_verification(&content, &tree)?);
        findings.extend(self.check_owner_checks(&content, &tree)?);
        findings.extend(self.check_arithmetic_operations(&content, &tree)?);
        findings.extend(self.check_cpi_vulnerabilities(&content, &tree)?);
        findings.extend(self.check_pda_vulnerabilities(&content, &tree)?);
        findings.extend(self.check_sysvar_usage(&content, &tree)?);
        findings.extend(self.check_rent_exemption(&content, &tree)?);
        findings.extend(self.check_type_confusion(&content, &tree)?);
        findings.extend(self.check_duplicate_mutable_accounts(&content, &tree)?);
        
        // Run sub-analyzers
        let account_issues = self.account_validator.analyze(&content, &tree)?;
        findings.extend(account_issues);
        
        let cpi_issues = self.cpi_analyzer.analyze(&content, &tree)?;
        findings.extend(cpi_issues);
        
        let signer_issues = self.signer_analyzer.analyze(&content, &tree)?;
        findings.extend(signer_issues);
        
        let ownership_issues = self.ownership_analyzer.analyze(&content, &tree)?;
        findings.extend(ownership_issues);
        
        let arithmetic_issues = self.arithmetic_analyzer.analyze(&content, &tree)?;
        findings.extend(arithmetic_issues);
        
        let performance_issues = self.performance_analyzer.analyze(&content, &tree)?;
        findings.extend(performance_issues);
        
        Ok(SolanaAnalysisResult {
            findings: findings.clone(),
            security_score: self.calculate_security_score(&findings),
            performance_score: self.calculate_performance_score(&findings),
            best_practices_score: self.calculate_best_practices_score(&findings),
            optimization_suggestions: self.generate_optimization_suggestions(&findings),
        })
    }
    
    fn check_account_validation(&self, content: &str, tree: &tree_sitter::Tree) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for missing account validation
        let account_patterns = vec![
            r"AccountInfo\s*<\s*'_\s*>",
            r"next_account_info",
            r"accounts\s*\.\s*iter\s*\(\s*\)",
        ];
        
        let validation_patterns = vec![
            r"is_signer",
            r"is_writable",
            r"owner\s*==",
            r"key\s*==",
        ];
        
        for pattern in account_patterns {
            let regex = Regex::new(pattern).unwrap();
            for mat in regex.find_iter(content) {
                let pos = mat.start();
                let (line, column) = self.get_line_column(content, pos);
                
                // Check if validation follows within reasonable distance
                let context = self.get_context_around(content, pos, 500);
                let mut has_validation = false;
                
                for val_pattern in &validation_patterns {
                    if Regex::new(val_pattern).unwrap().is_match(&context) {
                        has_validation = true;
                        break;
                    }
                }
                
                if !has_validation {
                    findings.push(Finding {
                        id: "SOL-ACC-001".to_string(),
                        severity: Severity::Critical,
                        category: "Solana/AccountValidation".to_string(),
                        title: "Missing account validation".to_string(),
                        description: 
                            "Account used without proper validation. This could allow attackers to pass \
                            arbitrary accounts leading to fund theft or program manipulation.".to_string(),
                        file: "".to_string(),
                        line,
                        column,
                        code_snippet: Some(self.get_code_snippet(content, line)),
                        remediation: Some(
                            "Validate account ownership, signer status, and writability before use".to_string()
                        ),
                        references: vec![
                            "https://docs.solana.com/developing/programming-model/accounts".to_string()
                        ],
                        ai_consensus: None,
                    });
                }
            }
        }
        
        Ok(findings)
    }
    
    fn check_signer_verification(&self, content: &str, tree: &tree_sitter::Tree) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for operations that should require signer verification
        let sensitive_ops = vec![
            r"transfer\s*\(",
            r"transfer_lamports\s*\(",
            r"set_authority\s*\(",
            r"mint_to\s*\(",
            r"burn\s*\(",
            r"close_account\s*\(",
        ];
        
        for pattern in sensitive_ops {
            let regex = Regex::new(pattern).unwrap();
            for mat in regex.find_iter(content) {
                let pos = mat.start();
                let (line, column) = self.get_line_column(content, pos);
                
                // Check if signer check precedes this operation
                let prefix = if pos > 500 { &content[pos-500..pos] } else { &content[0..pos] };
                if !prefix.contains("is_signer") && !prefix.contains("require_signer") {
                    findings.push(Finding {
                        id: "SOL-SIGN-001".to_string(),
                        severity: Severity::Critical,
                        category: "Solana/SignerCheck".to_string(),
                        title: "Missing signer verification".to_string(),
                        description: format!(
                            "Sensitive operation '{}' performed without verifying signer. \
                            This could allow unauthorized users to execute privileged operations.",
                            pattern.replace(r"\s*\(", "")
                        ),
                        file: "".to_string(),
                        line,
                        column,
                        code_snippet: Some(self.get_code_snippet(content, line)),
                        remediation: Some(
                            "Check account.is_signer before performing sensitive operations".to_string()
                        ),
                        references: vec![
                            "https://docs.solana.com/developing/programming-model/transactions#signatures".to_string()
                        ],
                        ai_consensus: None,
                    });
                }
            }
        }
        
        Ok(findings)
    }
    
    fn check_owner_checks(&self, content: &str, tree: &tree_sitter::Tree) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for program-owned account operations without owner verification
        let ownership_patterns = vec![
            (r"AccountInfo", r"owner"),
            (r"data_as_mut_slice", r"owner\s*=="),
            (r"try_borrow_mut_data", r"owner"),
        ];
        
        for (op_pattern, check_pattern) in ownership_patterns {
            let op_regex = Regex::new(op_pattern).unwrap();
            let check_regex = Regex::new(check_pattern).unwrap();
            
            for mat in op_regex.find_iter(content) {
                let pos = mat.start();
                let (line, column) = self.get_line_column(content, pos);
                
                // Check surrounding context for owner verification
                let context = self.get_context_around(content, pos, 300);
                if !check_regex.is_match(&context) {
                    findings.push(Finding {
                        id: "SOL-OWN-001".to_string(),
                        severity: Severity::High,
                        category: "Solana/Ownership".to_string(),
                        title: "Missing owner verification".to_string(),
                        description: 
                            "Account data accessed without verifying program ownership. \
                            This could allow manipulation of accounts owned by other programs.".to_string(),
                        file: "".to_string(),
                        line,
                        column,
                        code_snippet: Some(self.get_code_snippet(content, line)),
                        remediation: Some(
                            "Verify account.owner == program_id before accessing account data".to_string()
                        ),
                        references: vec![
                            "https://docs.solana.com/developing/programming-model/accounts#ownership".to_string()
                        ],
                        ai_consensus: None,
                    });
                }
            }
        }
        
        Ok(findings)
    }
    
    fn check_arithmetic_operations(&self, content: &str, tree: &tree_sitter::Tree) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for unsafe arithmetic operations
        let arithmetic_patterns = vec![
            (r"[^+=]\+[^=]", "addition"),
            (r"[^-=]-[^=]", "subtraction"),
            (r"[^*=]\*[^=]", "multiplication"),
            (r"[^/=]/[^=]", "division"),
        ];
        
        let safe_patterns = vec![
            r"checked_add",
            r"checked_sub",
            r"checked_mul",
            r"checked_div",
            r"saturating_add",
            r"saturating_sub",
            r"wrapping_add",
            r"wrapping_sub",
        ];
        
        for (pattern, op_name) in arithmetic_patterns {
            let regex = Regex::new(pattern).unwrap();
            for mat in regex.find_iter(content) {
                let pos = mat.start();
                let (line, column) = self.get_line_column(content, pos);
                
                // Check if this is inside a safe operation
                let context = self.get_context_around(content, pos, 100);
                let mut is_safe = false;
                
                for safe_pattern in &safe_patterns {
                    if context.contains(safe_pattern) {
                        is_safe = true;
                        break;
                    }
                }
                
                if !is_safe && !self.is_in_test_code(content, pos) {
                    findings.push(Finding {
                        id: "SOL-ARITH-001".to_string(),
                        severity: Severity::High,
                        category: "Solana/Arithmetic".to_string(),
                        title: format!("Unsafe {} operation", op_name),
                        description: format!(
                            "Unchecked {} operation detected. This could lead to integer \
                            overflow/underflow vulnerabilities allowing attackers to manipulate balances.",
                            op_name
                        ),
                        file: "".to_string(),
                        line,
                        column,
                        code_snippet: Some(self.get_code_snippet(content, line)),
                        remediation: Some(format!(
                            "Use checked_{} or saturating_{} methods instead",
                            if op_name == "addition" { "add" } else if op_name == "subtraction" { "sub" } 
                            else if op_name == "multiplication" { "mul" } else { "div" },
                            if op_name == "addition" { "add" } else if op_name == "subtraction" { "sub" } 
                            else if op_name == "multiplication" { "mul" } else { "div" }
                        )),
                        references: vec![
                            "https://github.com/crytic/building-secure-contracts/tree/master/not-so-smart-contracts/solana".to_string()
                        ],
                        ai_consensus: None,
                    });
                }
            }
        }
        
        Ok(findings)
    }
    
    fn check_cpi_vulnerabilities(&self, content: &str, tree: &tree_sitter::Tree) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for Cross-Program Invocation vulnerabilities
        let cpi_patterns = vec![
            r"invoke\s*\(",
            r"invoke_signed\s*\(",
        ];
        
        for pattern in cpi_patterns {
            let regex = Regex::new(pattern).unwrap();
            for mat in regex.find_iter(content) {
                let pos = mat.start();
                let (line, column) = self.get_line_column(content, pos);
                
                // Check if program ID is validated
                let context = self.get_context_around(content, pos, 300);
                if !context.contains("program_id") || !context.contains("==") {
                    findings.push(Finding {
                        id: "SOL-CPI-001".to_string(),
                        severity: Severity::Critical,
                        category: "Solana/CPI".to_string(),
                        title: "Unvalidated cross-program invocation".to_string(),
                        description: 
                            "CPI performed without validating target program ID. This could allow \
                            attackers to redirect calls to malicious programs.".to_string(),
                        file: "".to_string(),
                        line,
                        column,
                        code_snippet: Some(self.get_code_snippet(content, line)),
                        remediation: Some(
                            "Validate the target program ID before making cross-program invocations".to_string()
                        ),
                        references: vec![
                            "https://docs.solana.com/developing/programming-model/calling-between-programs".to_string()
                        ],
                        ai_consensus: None,
                    });
                }
            }
        }
        
        Ok(findings)
    }
    
    fn check_pda_vulnerabilities(&self, content: &str, tree: &tree_sitter::Tree) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for PDA seed vulnerabilities
        let pda_patterns = vec![
            r"find_program_address\s*\(",
            r"create_program_address\s*\(",
        ];
        
        for pattern in pda_patterns {
            let regex = Regex::new(pattern).unwrap();
            for mat in regex.find_iter(content) {
                let pos = mat.start();
                let (line, column) = self.get_line_column(content, pos);
                
                // Check if seeds include user-controlled data without validation
                let context = self.get_context_around(content, pos, 200);
                if context.contains("pubkey") && !context.contains("canonical_bump") {
                    findings.push(Finding {
                        id: "SOL-PDA-001".to_string(),
                        severity: Severity::Medium,
                        category: "Solana/PDA".to_string(),
                        title: "PDA seed collision vulnerability".to_string(),
                        description: 
                            "PDA created with user-controlled seeds without canonical bump. \
                            This could lead to seed collision attacks.".to_string(),
                        file: "".to_string(),
                        line,
                        column,
                        code_snippet: Some(self.get_code_snippet(content, line)),
                        remediation: Some(
                            "Use canonical bumps and validate all user inputs used in PDA seeds".to_string()
                        ),
                        references: vec![
                            "https://docs.solana.com/developing/programming-model/calling-between-programs#program-derived-addresses".to_string()
                        ],
                        ai_consensus: None,
                    });
                }
            }
        }
        
        Ok(findings)
    }
    
    fn check_sysvar_usage(&self, content: &str, tree: &tree_sitter::Tree) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for deprecated sysvar usage
        let deprecated_sysvars = vec![
            (r"recent_blockhashes", "RecentBlockhashes"),
            (r"fees", "Fees"),
        ];
        
        for (pattern, name) in deprecated_sysvars {
            let regex = Regex::new(pattern).unwrap();
            for mat in regex.find_iter(content) {
                let pos = mat.start();
                let (line, column) = self.get_line_column(content, pos);
                
                findings.push(Finding {
                    id: "SOL-SYS-001".to_string(),
                    severity: Severity::Low,
                    category: "Solana/Sysvar".to_string(),
                    title: format!("Use of deprecated sysvar: {}", name),
                    description: format!(
                        "The {} sysvar is deprecated and may be removed in future versions.",
                        name
                    ),
                    file: "".to_string(),
                    line,
                    column,
                    code_snippet: Some(self.get_code_snippet(content, line)),
                    remediation: Some(
                        "Use current alternatives as specified in Solana documentation".to_string()
                    ),
                    references: vec![
                        "https://docs.solana.com/developing/runtime-facilities/sysvars".to_string()
                    ],
                    ai_consensus: None,
                });
            }
        }
        
        Ok(findings)
    }
    
    fn check_rent_exemption(&self, content: &str, tree: &tree_sitter::Tree) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for proper rent exemption handling
        let account_creation_patterns = vec![
            r"create_account\s*\(",
            r"allocate\s*\(",
        ];
        
        for pattern in account_creation_patterns {
            let regex = Regex::new(pattern).unwrap();
            for mat in regex.find_iter(content) {
                let pos = mat.start();
                let (line, column) = self.get_line_column(content, pos);
                
                // Check if rent exemption is properly calculated
                let context = self.get_context_around(content, pos, 300);
                if !context.contains("minimum_balance") && !context.contains("rent") {
                    findings.push(Finding {
                        id: "SOL-RENT-001".to_string(),
                        severity: Severity::Medium,
                        category: "Solana/RentExemption".to_string(),
                        title: "Missing rent exemption calculation".to_string(),
                        description: 
                            "Account created without proper rent exemption calculation. \
                            This could lead to accounts being garbage collected.".to_string(),
                        file: "".to_string(),
                        line,
                        column,
                        code_snippet: Some(self.get_code_snippet(content, line)),
                        remediation: Some(
                            "Calculate minimum balance for rent exemption using Rent sysvar".to_string()
                        ),
                        references: vec![
                            "https://docs.solana.com/developing/programming-model/accounts#rent".to_string()
                        ],
                        ai_consensus: None,
                    });
                }
            }
        }
        
        Ok(findings)
    }
    
    fn check_type_confusion(&self, content: &str, tree: &tree_sitter::Tree) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for potential type confusion vulnerabilities
        let deserialization_patterns = vec![
            r"try_from_slice\s*\(",
            r"unpack\s*\(",
            r"from_bytes\s*\(",
        ];
        
        for pattern in deserialization_patterns {
            let regex = Regex::new(pattern).unwrap();
            for mat in regex.find_iter(content) {
                let pos = mat.start();
                let (line, column) = self.get_line_column(content, pos);
                
                // Check if discriminator or type checking is present
                let context = self.get_context_around(content, pos, 200);
                if !context.contains("discriminator") && !context.contains("account_type") {
                    findings.push(Finding {
                        id: "SOL-TYPE-001".to_string(),
                        severity: Severity::High,
                        category: "Solana/TypeSafety".to_string(),
                        title: "Potential type confusion vulnerability".to_string(),
                        description: 
                            "Account deserialization without type verification. This could allow \
                            attackers to pass wrong account types leading to logic errors.".to_string(),
                        file: "".to_string(),
                        line,
                        column,
                        code_snippet: Some(self.get_code_snippet(content, line)),
                        remediation: Some(
                            "Add discriminator or type field validation before deserialization".to_string()
                        ),
                        references: vec![
                            "https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/2-type-confusion".to_string()
                        ],
                        ai_consensus: None,
                    });
                }
            }
        }
        
        Ok(findings)
    }
    
    fn check_duplicate_mutable_accounts(&self, content: &str, tree: &tree_sitter::Tree) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for duplicate mutable accounts vulnerability
        let account_patterns = vec![
            r"accounts\s*:\s*&\[AccountInfo\]",
            r"ctx\.accounts",
        ];
        
        for pattern in account_patterns {
            let regex = Regex::new(pattern).unwrap();
            for mat in regex.find_iter(content) {
                let pos = mat.start();
                let (line, column) = self.get_line_column(content, pos);
                
                // Check if there's validation for duplicate accounts
                let context = self.get_context_around(content, pos, 500);
                if context.contains("is_writable") && !context.contains("key ==") {
                    findings.push(Finding {
                        id: "SOL-DUP-001".to_string(),
                        severity: Severity::High,
                        category: "Solana/DuplicateAccounts".to_string(),
                        title: "Missing duplicate mutable account validation".to_string(),
                        description: 
                            "Multiple mutable accounts without duplicate checking. Attackers could \
                            pass the same account multiple times to bypass security checks.".to_string(),
                        file: "".to_string(),
                        line,
                        column,
                        code_snippet: Some(self.get_code_snippet(content, line)),
                        remediation: Some(
                            "Check that all mutable accounts have unique public keys".to_string()
                        ),
                        references: vec![
                            "https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/6-duplicate-mutable-accounts".to_string()
                        ],
                        ai_consensus: None,
                    });
                }
            }
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
    
    fn is_in_test_code(&self, content: &str, pos: usize) -> bool {
        // Simple heuristic to check if we're in test code
        let context = self.get_context_around(content, pos, 1000);
        context.contains("#[test]") || context.contains("#[cfg(test)]") || context.contains("mod tests")
    }
    
    fn calculate_security_score(&self, findings: &[Finding]) -> f32 {
        let critical_count = findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high_count = findings.iter().filter(|f| f.severity == Severity::High).count();
        let medium_count = findings.iter().filter(|f| f.severity == Severity::Medium).count();
        
        let score = 100.0 - (critical_count as f32 * 20.0) - (high_count as f32 * 10.0) - (medium_count as f32 * 5.0);
        score.max(0.0)
    }
    
    fn calculate_performance_score(&self, findings: &[Finding]) -> f32 {
        let perf_issues = findings.iter()
            .filter(|f| f.category.contains("Performance"))
            .count();
        
        let score = 100.0 - (perf_issues as f32 * 10.0);
        score.max(0.0)
    }
    
    fn calculate_best_practices_score(&self, findings: &[Finding]) -> f32 {
        let total_issues = findings.len();
        let score = 100.0 - (total_issues as f32 * 2.0);
        score.max(0.0)
    }
    
    fn generate_optimization_suggestions(&self, findings: &[Finding]) -> Vec<String> {
        let mut suggestions = Vec::new();
        
        // Generate suggestions based on findings
        let has_arithmetic = findings.iter().any(|f| f.category.contains("Arithmetic"));
        if has_arithmetic {
            suggestions.push("Consider using checked arithmetic operations throughout the program".to_string());
        }
        
        let has_cpi = findings.iter().any(|f| f.category.contains("CPI"));
        if has_cpi {
            suggestions.push("Implement strict CPI validation with program ID allowlists".to_string());
        }
        
        let has_account_issues = findings.iter().any(|f| f.category.contains("Account"));
        if has_account_issues {
            suggestions.push("Use Anchor framework for automatic account validation".to_string());
        }
        
        suggestions
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolanaAnalysisResult {
    pub findings: Vec<Finding>,
    pub security_score: f32,
    pub performance_score: f32,
    pub best_practices_score: f32,
    pub optimization_suggestions: Vec<String>,
}
