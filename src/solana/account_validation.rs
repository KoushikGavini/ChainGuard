use crate::{Result, Finding, Severity};
use tree_sitter::Tree;
use regex::Regex;

pub struct AccountValidator {
    patterns: Vec<AccountPattern>,
}

struct AccountPattern {
    pattern: Regex,
    severity: Severity,
    id: String,
    title: String,
    description: String,
}

impl AccountValidator {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                AccountPattern {
                    pattern: Regex::new(r"accounts\.get\(\d+\)").unwrap(),
                    severity: Severity::Medium,
                    id: "SOL-ACC-002".to_string(),
                    title: "Hard-coded account index access".to_string(),
                    description: "Using hard-coded indices to access accounts is error-prone and makes code harder to maintain".to_string(),
                },
                AccountPattern {
                    pattern: Regex::new(r"lamports\(\)\s*>\s*0").unwrap(),
                    severity: Severity::Low,
                    id: "SOL-ACC-003".to_string(),
                    title: "Lamport balance check without rent consideration".to_string(),
                    description: "Checking if lamports > 0 doesn't account for rent-exempt minimum balance".to_string(),
                },
                AccountPattern {
                    pattern: Regex::new(r"data\.len\(\)\s*==\s*0").unwrap(),
                    severity: Severity::Medium,
                    id: "SOL-ACC-004".to_string(),
                    title: "Account initialization check using data length".to_string(),
                    description: "Checking data.len() == 0 is not reliable for account initialization status".to_string(),
                },
            ],
        }
    }
    
    pub fn analyze(&self, content: &str, tree: &Tree) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check each pattern
        for account_pattern in &self.patterns {
            for mat in account_pattern.pattern.find_iter(content) {
                let pos = mat.start();
                let (line, column) = self.get_line_column(content, pos);
                
                findings.push(Finding {
                    id: account_pattern.id.clone(),
                    severity: account_pattern.severity,
                    category: "Solana/AccountValidation".to_string(),
                    title: account_pattern.title.clone(),
                    description: account_pattern.description.clone(),
                    file: "".to_string(),
                    line,
                    column,
                    code_snippet: Some(self.get_code_snippet(content, line)),
                    remediation: Some(self.get_remediation(&account_pattern.id)),
                    references: vec![
                        "https://docs.solana.com/developing/programming-model/accounts".to_string()
                    ],
                    ai_consensus: None,
                });
            }
        }
        
        // Additional complex checks
        findings.extend(self.check_discriminator_pattern(content)?);
        findings.extend(self.check_account_close_pattern(content)?);
        
        Ok(findings)
    }
    
    fn check_discriminator_pattern(&self, content: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for accounts that should have discriminators
        if content.contains("borsh::BorshDeserialize") || content.contains("anchor_lang") {
            if !content.contains("discriminator") && !content.contains("account_discriminator") {
                findings.push(Finding {
                    id: "SOL-ACC-005".to_string(),
                    severity: Severity::High,
                    category: "Solana/AccountValidation".to_string(),
                    title: "Missing account discriminator".to_string(),
                    description: 
                        "Account types should have discriminators to prevent type confusion attacks".to_string(),
                    file: "".to_string(),
                    line: 1,
                    column: 1,
                    code_snippet: None,
                    remediation: Some(
                        "Add an 8-byte discriminator field at the beginning of account data".to_string()
                    ),
                    references: vec![
                        "https://www.anchor-lang.com/docs/account-types".to_string()
                    ],
                    ai_consensus: None,
                });
            }
        }
        
        Ok(findings)
    }
    
    fn check_account_close_pattern(&self, content: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for account closing patterns
        let close_pattern = Regex::new(r"lamports\.borrow_mut\(\)\s*=\s*0").unwrap();
        
        for mat in close_pattern.find_iter(content) {
            let pos = mat.start();
            let (line, column) = self.get_line_column(content, pos);
            
            // Check if data is also cleared
            let context = self.get_context_around(content, pos, 200);
            if !context.contains("data.borrow_mut().fill(0)") && !context.contains("assign") {
                findings.push(Finding {
                    id: "SOL-ACC-006".to_string(),
                    severity: Severity::High,
                    category: "Solana/AccountValidation".to_string(),
                    title: "Incomplete account closure".to_string(),
                    description: 
                        "Account closed without clearing data or reassigning ownership. This could lead to account resurrection attacks".to_string(),
                    file: "".to_string(),
                    line,
                    column,
                    code_snippet: Some(self.get_code_snippet(content, line)),
                    remediation: Some(
                        "Clear account data and reassign to system program when closing accounts".to_string()
                    ),
                    references: vec![
                        "https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/9-closing-accounts".to_string()
                    ],
                    ai_consensus: None,
                });
            }
        }
        
        Ok(findings)
    }
    
    fn get_remediation(&self, id: &str) -> String {
        match id {
            "SOL-ACC-002" => "Use named account structs or constants for account indices".to_string(),
            "SOL-ACC-003" => "Use Rent::get()?.minimum_balance(data_len) for proper rent calculations".to_string(),
            "SOL-ACC-004" => "Use a proper initialization flag or discriminator in account data".to_string(),
            _ => "Follow Solana account validation best practices".to_string(),
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