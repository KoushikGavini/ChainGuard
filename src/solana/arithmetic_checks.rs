use crate::{Result, Finding, Severity};
use tree_sitter::Tree;
use regex::Regex;

pub struct ArithmeticAnalyzer {
    patterns: Vec<ArithmeticPattern>,
}

struct ArithmeticPattern {
    pattern: Regex,
    operation: String,
    severity: Severity,
}

impl ArithmeticAnalyzer {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                ArithmeticPattern {
                    pattern: Regex::new(r"(\w+)\s*\+\s*(\w+)").unwrap(),
                    operation: "addition".to_string(),
                    severity: Severity::High,
                },
                ArithmeticPattern {
                    pattern: Regex::new(r"(\w+)\s*-\s*(\w+)").unwrap(),
                    operation: "subtraction".to_string(),
                    severity: Severity::High,
                },
                ArithmeticPattern {
                    pattern: Regex::new(r"(\w+)\s*\*\s*(\w+)").unwrap(),
                    operation: "multiplication".to_string(),
                    severity: Severity::High,
                },
                ArithmeticPattern {
                    pattern: Regex::new(r"(\w+)\s*/\s*(\w+)").unwrap(),
                    operation: "division".to_string(),
                    severity: Severity::High,
                },
            ],
        }
    }
    
    pub fn analyze(&self, content: &str, _tree: &Tree) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Safe arithmetic methods that don't need warnings
        let safe_methods = vec![
            "checked_add",
            "checked_sub",
            "checked_mul",
            "checked_div",
            "saturating_add",
            "saturating_sub",
            "saturating_mul",
            "wrapping_add",
            "wrapping_sub",
            "wrapping_mul",
            "overflowing_add",
            "overflowing_sub",
            "overflowing_mul",
        ];
        
        for arith_pattern in &self.patterns {
            for mat in arith_pattern.pattern.find_iter(content) {
                let pos = mat.start();
                let (line, column) = self.get_line_column(content, pos);
                
                // Get context to check if it's safe
                let context = self.get_context_around(content, pos, 100);
                
                // Skip if it's in a safe method call
                let mut is_safe = false;
                for safe_method in &safe_methods {
                    if context.contains(safe_method) {
                        is_safe = true;
                        break;
                    }
                }
                
                // Skip if it's in test code or comments
                if is_safe || self.is_in_test_or_comment(content, pos) {
                    continue;
                }
                
                // Check for specific vulnerable patterns
                if self.is_balance_operation(&context) {
                    findings.push(Finding {
                        id: format!("SOL-ARITH-BAL-{}", arith_pattern.operation.to_uppercase()),
                        severity: Severity::Critical,
                        category: "Solana/Arithmetic".to_string(),
                        title: format!("Unsafe {} on balance/lamports", arith_pattern.operation),
                        description: format!(
                            "Unsafe {} operation detected on what appears to be a balance or lamports value. \
                            This could lead to overflow/underflow allowing attackers to mint tokens or drain accounts.",
                            arith_pattern.operation
                        ),
                        file: "".to_string(),
                        line,
                        column,
                        code_snippet: Some(self.get_code_snippet(content, line)),
                        remediation: Some(self.get_safe_alternative(&arith_pattern.operation)),
                        references: vec![
                            "https://github.com/crytic/building-secure-contracts/tree/master/not-so-smart-contracts/solana/arithmetic-overflow".to_string()
                        ],
                        ai_consensus: None,
                    });
                } else {
                    findings.push(Finding {
                        id: format!("SOL-ARITH-{}", arith_pattern.operation.to_uppercase()),
                        severity: arith_pattern.severity,
                        category: "Solana/Arithmetic".to_string(),
                        title: format!("Unsafe {} operation", arith_pattern.operation),
                        description: format!(
                            "Unsafe {} operation detected. This could lead to integer overflow/underflow vulnerabilities.",
                            arith_pattern.operation
                        ),
                        file: "".to_string(),
                        line,
                        column,
                        code_snippet: Some(self.get_code_snippet(content, line)),
                        remediation: Some(self.get_safe_alternative(&arith_pattern.operation)),
                        references: vec![
                            "https://doc.rust-lang.org/book/ch03-02-data-types.html#integer-overflow".to_string()
                        ],
                        ai_consensus: None,
                    });
                }
            }
        }
        
        // Check for specific patterns
        findings.extend(self.check_as_conversions(content)?);
        findings.extend(self.check_unchecked_pow(content)?);
        
        Ok(findings)
    }
    
    fn check_as_conversions(&self, content: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for potentially lossy type conversions
        let as_pattern = Regex::new(r"as\s+(u8|u16|u32|u64|u128|i8|i16|i32|i64|i128)").unwrap();
        
        for mat in as_pattern.find_iter(content) {
            let pos = mat.start();
            let (line, column) = self.get_line_column(content, pos);
            
            // Get the context to understand what's being converted
            let context = self.get_context_around(content, pos, 50);
            
            // Check if it's a narrowing conversion
            if self.is_narrowing_conversion(&context) {
                findings.push(Finding {
                    id: "SOL-ARITH-CAST".to_string(),
                    severity: Severity::Medium,
                    category: "Solana/Arithmetic".to_string(),
                    title: "Potentially lossy type conversion".to_string(),
                    description: 
                        "Using 'as' for type conversion can be lossy and may truncate values. \
                        This could lead to unexpected behavior.".to_string(),
                    file: "".to_string(),
                    line,
                    column,
                    code_snippet: Some(self.get_code_snippet(content, line)),
                    remediation: Some(
                        "Use try_from() or try_into() for safe conversions that return Result".to_string()
                    ),
                    references: vec![],
                    ai_consensus: None,
                });
            }
        }
        
        Ok(findings)
    }
    
    fn check_unchecked_pow(&self, content: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Check for pow operations without overflow checks
        let pow_pattern = Regex::new(r"\.pow\s*\(").unwrap();
        
        for mat in pow_pattern.find_iter(content) {
            let pos = mat.start();
            let (line, column) = self.get_line_column(content, pos);
            
            let context = self.get_context_around(content, pos, 100);
            if !context.contains("checked_pow") {
                findings.push(Finding {
                    id: "SOL-ARITH-POW".to_string(),
                    severity: Severity::High,
                    category: "Solana/Arithmetic".to_string(),
                    title: "Unchecked power operation".to_string(),
                    description: 
                        "Power operations can overflow quickly. Use checked_pow to prevent overflow.".to_string(),
                    file: "".to_string(),
                    line,
                    column,
                    code_snippet: Some(self.get_code_snippet(content, line)),
                    remediation: Some(
                        "Replace .pow() with .checked_pow() and handle the Option result".to_string()
                    ),
                    references: vec![],
                    ai_consensus: None,
                });
            }
        }
        
        Ok(findings)
    }
    
    fn is_balance_operation(&self, context: &str) -> bool {
        let balance_indicators = vec![
            "lamports",
            "balance",
            "amount",
            "total_supply",
            "mint_amount",
            "transfer_amount",
            "token",
        ];
        
        balance_indicators.iter().any(|indicator| context.to_lowercase().contains(indicator))
    }
    
    fn is_narrowing_conversion(&self, context: &str) -> bool {
        // Simple heuristic: check if converting from larger to smaller type
        let narrowing_patterns = vec![
            ("u64", "u32"),
            ("u64", "u16"),
            ("u64", "u8"),
            ("u128", "u64"),
            ("u128", "u32"),
            ("i64", "i32"),
            ("i64", "i16"),
            ("i64", "i8"),
        ];
        
        narrowing_patterns.iter().any(|(from, to)| 
            context.contains(from) && context.contains(to)
        )
    }
    
    fn is_in_test_or_comment(&self, content: &str, pos: usize) -> bool {
        let context = self.get_context_around(content, pos, 500);
        context.contains("#[test]") || 
        context.contains("#[cfg(test)]") || 
        context.contains("mod tests") ||
        context.contains("//") ||
        context.contains("/*")
    }
    
    fn get_safe_alternative(&self, operation: &str) -> String {
        match operation {
            "addition" => "Use checked_add() or saturating_add() instead of +".to_string(),
            "subtraction" => "Use checked_sub() or saturating_sub() instead of -".to_string(),
            "multiplication" => "Use checked_mul() or saturating_mul() instead of *".to_string(),
            "division" => "Use checked_div() and ensure divisor is not zero".to_string(),
            _ => "Use checked arithmetic methods".to_string(),
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