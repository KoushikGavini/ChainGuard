use crate::{Result, Finding, Severity};
use tree_sitter::Tree;
use regex::Regex;

pub struct CPIAnalyzer {
    cpi_patterns: Vec<CPIPattern>,
}

struct CPIPattern {
    pattern: Regex,
    severity: Severity,
    id: String,
    title: String,
    description: String,
}

impl CPIAnalyzer {
    pub fn new() -> Self {
        Self {
            cpi_patterns: vec![
                CPIPattern {
                    pattern: Regex::new(r"invoke_signed_unchecked").unwrap(),
                    severity: Severity::Critical,
                    id: "SOL-CPI-002".to_string(),
                    title: "Use of unchecked CPI invocation".to_string(),
                    description: "invoke_signed_unchecked bypasses important security checks and should be avoided".to_string(),
                },
                CPIPattern {
                    pattern: Regex::new(r"remaining_accounts").unwrap(),
                    severity: Severity::High,
                    id: "SOL-CPI-003".to_string(),
                    title: "Use of remaining_accounts in CPI".to_string(),
                    description: "Passing remaining_accounts to CPI calls can lead to unexpected account manipulation".to_string(),
                },
                CPIPattern {
                    pattern: Regex::new(r"system_instruction::transfer\s*\([^,]+,[^,]+,\s*0\s*\)").unwrap(),
                    severity: Severity::Low,
                    id: "SOL-CPI-004".to_string(),
                    title: "Zero-value transfer detected".to_string(),
                    description: "Transferring 0 lamports may indicate logic error or unnecessary CPI".to_string(),
                },
            ],
        }
    }
    
    pub fn analyze(&self, content: &str, tree: &Tree) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check each CPI pattern
        for cpi_pattern in &self.cpi_patterns {
            for mat in cpi_pattern.pattern.find_iter(content) {
                let pos = mat.start();
                let (line, column) = self.get_line_column(content, pos);
                
                findings.push(Finding {
                    id: cpi_pattern.id.clone(),
                    severity: cpi_pattern.severity,
                    category: "Solana/CPI".to_string(),
                    title: cpi_pattern.title.clone(),
                    description: cpi_pattern.description.clone(),
                    file: "".to_string(),
                    line,
                    column,
                    code_snippet: Some(self.get_code_snippet(content, line)),
                    remediation: Some(self.get_remediation(&cpi_pattern.id)),
                    references: vec![
                        "https://docs.solana.com/developing/programming-model/calling-between-programs".to_string()
                    ],
                    ai_consensus: None,
                });
            }
        }
        
        // Additional complex CPI checks
        findings.extend(self.check_arbitrary_cpi(content)?);
        findings.extend(self.check_signer_seeds(content)?);
        findings.extend(self.check_account_info_reuse(content)?);
        
        Ok(findings)
    }
    
    fn check_arbitrary_cpi(&self, content: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for CPI calls with user-provided program IDs
        let invoke_pattern = Regex::new(r"invoke\s*\(\s*&").unwrap();
        
        for mat in invoke_pattern.find_iter(content) {
            let pos = mat.start();
            let (line, column) = self.get_line_column(content, pos);
            
            // Check if the program ID comes from user input
            let context = self.get_context_around(content, pos, 300);
            if context.contains("instruction.program_id") || context.contains("accounts.") {
                if !context.contains("program_id ==") && !context.contains("check_program_id") {
                    findings.push(Finding {
                        id: "SOL-CPI-005".to_string(),
                        severity: Severity::Critical,
                        category: "Solana/CPI".to_string(),
                        title: "Arbitrary program invocation".to_string(),
                        description: 
                            "CPI target program ID appears to come from user input without validation. \
                            This could allow attackers to invoke arbitrary programs".to_string(),
                        file: "".to_string(),
                        line,
                        column,
                        code_snippet: Some(self.get_code_snippet(content, line)),
                        remediation: Some(
                            "Validate program IDs against a whitelist before CPI invocation".to_string()
                        ),
                        references: vec![
                            "https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/7-arbitrary-cpi".to_string()
                        ],
                        ai_consensus: None,
                    });
                }
            }
        }
        
        Ok(findings)
    }
    
    fn check_signer_seeds(&self, content: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for potential signer seed issues
        let invoke_signed_pattern = Regex::new(r"invoke_signed\s*\(").unwrap();
        
        for mat in invoke_signed_pattern.find_iter(content) {
            let pos = mat.start();
            let (line, column) = self.get_line_column(content, pos);
            
            // Look for the signer seeds parameter
            let context = self.get_context_around(content, pos, 500);
            
            // Check for empty signer seeds
            if context.contains("&[]") || context.contains("vec![]") {
                findings.push(Finding {
                    id: "SOL-CPI-006".to_string(),
                    severity: Severity::High,
                    category: "Solana/CPI".to_string(),
                    title: "Empty signer seeds in CPI".to_string(),
                    description: 
                        "invoke_signed called with empty signer seeds. This defeats the purpose of signed invocation".to_string(),
                    file: "".to_string(),
                    line,
                    column,
                    code_snippet: Some(self.get_code_snippet(content, line)),
                    remediation: Some(
                        "Provide proper signer seeds for PDA signing or use regular invoke if no signing needed".to_string()
                    ),
                    references: vec![],
                    ai_consensus: None,
                });
            }
            
            // Check for hardcoded seeds
            if context.contains(r#"b""#) && !context.contains("SEED") && !context.contains("PREFIX") {
                findings.push(Finding {
                    id: "SOL-CPI-007".to_string(),
                    severity: Severity::Medium,
                    category: "Solana/CPI".to_string(),
                    title: "Hardcoded signer seeds".to_string(),
                    description: 
                        "Signer seeds appear to be hardcoded. Consider using constants for better maintainability".to_string(),
                    file: "".to_string(),
                    line,
                    column,
                    code_snippet: Some(self.get_code_snippet(content, line)),
                    remediation: Some(
                        "Define seed values as constants at the module level".to_string()
                    ),
                    references: vec![],
                    ai_consensus: None,
                });
            }
        }
        
        Ok(findings)
    }
    
    fn check_account_info_reuse(&self, content: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for potential account info reuse in CPI
        let account_metas_pattern = Regex::new(r"AccountMeta::new\s*\(").unwrap();
        
        let mut account_meta_positions = Vec::new();
        for mat in account_metas_pattern.find_iter(content) {
            account_meta_positions.push(mat.start());
        }
        
        // If we see multiple AccountMeta creations close together, check for reuse
        for window in account_meta_positions.windows(2) {
            if window[1] - window[0] < 200 {
                let context = &content[window[0]..window[1] + 100];
                
                // Look for the same account being used multiple times
                let account_refs: Vec<&str> = context.split("AccountMeta")
                    .filter_map(|s| s.split('(').nth(1))
                    .filter_map(|s| s.split(',').next())
                    .map(|s| s.trim())
                    .collect();
                
                // Check for duplicates
                for i in 0..account_refs.len() {
                    for j in i + 1..account_refs.len() {
                        if account_refs[i] == account_refs[j] && !account_refs[i].is_empty() {
                            let (line, column) = self.get_line_column(content, window[0]);
                            
                            findings.push(Finding {
                                id: "SOL-CPI-008".to_string(),
                                severity: Severity::Medium,
                                category: "Solana/CPI".to_string(),
                                title: "Duplicate account in CPI".to_string(),
                                description: format!(
                                    "Account '{}' appears multiple times in CPI instruction. \
                                    This might lead to unexpected behavior",
                                    account_refs[i]
                                ),
                                file: "".to_string(),
                                line,
                                column,
                                code_snippet: Some(self.get_code_snippet(content, line)),
                                remediation: Some(
                                    "Ensure each account appears only once in CPI unless explicitly required".to_string()
                                ),
                                references: vec![],
                                ai_consensus: None,
                            });
                            break;
                        }
                    }
                }
            }
        }
        
        Ok(findings)
    }
    
    fn get_remediation(&self, id: &str) -> String {
        match id {
            "SOL-CPI-002" => "Use invoke_signed with proper validation instead of unchecked variant".to_string(),
            "SOL-CPI-003" => "Explicitly pass only required accounts to CPI calls".to_string(),
            "SOL-CPI-004" => "Verify the transfer amount is correct and remove unnecessary zero transfers".to_string(),
            _ => "Follow Solana CPI security best practices".to_string(),
        }
    }
    
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
} 