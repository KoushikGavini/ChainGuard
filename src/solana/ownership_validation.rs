use crate::{Result, Finding, Severity};
use tree_sitter::Tree;
use regex::Regex;

pub struct OwnershipAnalyzer;

impl OwnershipAnalyzer {
    pub fn new() -> Self {
        Self
    }
    
    pub fn analyze(&self, content: &str, _tree: &Tree) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for account data access without owner validation
        let data_access_patterns = vec![
            r"try_borrow_mut_data",
            r"data_as_mut_slice",
            r"\.data\.borrow_mut\(\)",
            r"account_info\.data",
        ];
        
        for pattern in data_access_patterns {
            let regex = Regex::new(pattern).unwrap();
            
            for mat in regex.find_iter(content) {
                let pos = mat.start();
                let (line, column) = self.get_line_column(content, pos);
                
                // Check if owner validation exists before data access
                let prefix_context = if pos > 500 { 
                    &content[pos.saturating_sub(500)..pos] 
                } else { 
                    &content[0..pos] 
                };
                
                if !self.has_owner_check(prefix_context) {
                    findings.push(Finding {
                        id: "SOL-OWN-002".to_string(),
                        severity: Severity::High,
                        category: "Solana/Ownership".to_string(),
                        title: "Unvalidated account data access".to_string(),
                        description: 
                            "Account data accessed without verifying program ownership. \
                            This could lead to unauthorized data manipulation.".to_string(),
                        file: "".to_string(),
                        line,
                        column,
                        code_snippet: Some(self.get_code_snippet(content, line)),
                        remediation: Some(
                            "Verify account.owner == program_id before accessing data".to_string()
                        ),
                        references: vec![
                            "https://docs.solana.com/developing/programming-model/accounts#ownership-and-assignment-to-programs".to_string()
                        ],
                        ai_consensus: None,
                    });
                }
            }
        }
        
        // Check for system program ownership assumptions
        findings.extend(self.check_system_program_assumptions(content)?);
        
        Ok(findings)
    }
    
    fn check_system_program_assumptions(&self, content: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for unsafe system program assumptions
        let pattern = Regex::new(r"system_program::ID").unwrap();
        
        for mat in pattern.find_iter(content) {
            let pos = mat.start();
            let context = self.get_context_around(content, pos, 200);
            
            // Check if it's used in a comparison without proper validation
            if context.contains("!=") || context.contains("==") {
                let (line, column) = self.get_line_column(content, pos);
                
                findings.push(Finding {
                    id: "SOL-OWN-003".to_string(),
                    severity: Severity::Medium,
                    category: "Solana/Ownership".to_string(),
                    title: "Direct system program ID comparison".to_string(),
                    description: 
                        "Direct comparison with system program ID. Consider using helper functions \
                        for better readability and maintainability.".to_string(),
                    file: "".to_string(),
                    line,
                    column,
                    code_snippet: Some(self.get_code_snippet(content, line)),
                    remediation: Some(
                        "Use account.owner.eq(&system_program::ID) or create a helper function".to_string()
                    ),
                    references: vec![],
                    ai_consensus: None,
                });
            }
        }
        
        Ok(findings)
    }
    
    fn has_owner_check(&self, context: &str) -> bool {
        let owner_patterns = vec![
            "owner ==",
            "owner.eq",
            "check_owner",
            "verify_owner",
            "assert_owner",
            "#[account(owner =",
            "has_one = owner",
        ];
        
        owner_patterns.iter().any(|pattern| context.contains(pattern))
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