use crate::{Result, Finding, Severity};
use tree_sitter::Tree;
use regex::Regex;

pub struct SignerAnalyzer;

impl SignerAnalyzer {
    pub fn new() -> Self {
        Self
    }
    
    pub fn analyze(&self, content: &str, _tree: &Tree) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for missing signer checks before sensitive operations
        let sensitive_operations = vec![
            ("transfer", "Transfer operation"),
            ("close_account", "Account closure"),
            ("set_authority", "Authority change"),
            ("mint_to", "Token minting"),
            ("burn", "Token burning"),
            ("approve", "Token approval"),
        ];
        
        for (op, desc) in sensitive_operations {
            let pattern = Regex::new(&format!(r"{}.*?\(", op)).unwrap();
            
            for mat in pattern.find_iter(content) {
                let pos = mat.start();
                let (line, column) = self.get_line_column(content, pos);
                
                // Check if signer validation exists before this operation
                let prefix_context = if pos > 1000 { 
                    &content[pos.saturating_sub(1000)..pos] 
                } else { 
                    &content[0..pos] 
                };
                
                if !self.has_signer_check(prefix_context) {
                    findings.push(Finding {
                        id: format!("SOL-SIGN-{}", op.to_uppercase()),
                        severity: Severity::Critical,
                        category: "Solana/SignerCheck".to_string(),
                        title: format!("{} without signer verification", desc),
                        description: format!(
                            "{} operation found without prior signer verification. \
                            This could allow unauthorized users to perform privileged actions.",
                            desc
                        ),
                        file: "".to_string(),
                        line,
                        column,
                        code_snippet: Some(self.get_code_snippet(content, line)),
                        remediation: Some(format!(
                            "Add signer verification before {} operations: \
                            require!(account.is_signer, ErrorCode::Unauthorized);",
                            op
                        )),
                        references: vec![
                            "https://docs.solana.com/developing/programming-model/transactions#signatures".to_string()
                        ],
                        ai_consensus: None,
                    });
                }
            }
        }
        
        // Check for improper multi-sig validation
        findings.extend(self.check_multisig_patterns(content)?);
        
        Ok(findings)
    }
    
    fn check_multisig_patterns(&self, content: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for multi-sig patterns
        if content.contains("multisig") || content.contains("threshold") {
            // Check for proper threshold validation
            if !content.contains("required_signatures") && !content.contains("m_of_n") {
                findings.push(Finding {
                    id: "SOL-SIGN-MULTISIG".to_string(),
                    severity: Severity::High,
                    category: "Solana/SignerCheck".to_string(),
                    title: "Incomplete multi-signature implementation".to_string(),
                    description: 
                        "Multi-signature functionality detected but threshold validation appears incomplete".to_string(),
                    file: "".to_string(),
                    line: 1,
                    column: 1,
                    code_snippet: None,
                    remediation: Some(
                        "Implement proper threshold checking: verify that at least M of N signers have signed".to_string()
                    ),
                    references: vec![],
                    ai_consensus: None,
                });
            }
        }
        
        Ok(findings)
    }
    
    fn has_signer_check(&self, context: &str) -> bool {
        let signer_patterns = vec![
            "is_signer",
            "require_signer",
            "assert_signer",
            "check_signer",
            "verify_signer",
            "Signer",
            "#[account(signer)]",
        ];
        
        signer_patterns.iter().any(|pattern| context.contains(pattern))
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
} 