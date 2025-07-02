use crate::{Finding, Result, Severity};
use std::path::Path;
use tree_sitter::{Node, Parser};

pub struct ComplexityAnalyzer {
    parser: Parser,
}

#[derive(Debug)]
pub struct ComplexityMetrics {
    pub cyclomatic_complexity: f64,
    pub duplication_ratio: f64,
    pub function_count: usize,
    pub max_function_complexity: usize,
}

impl ComplexityAnalyzer {
    pub fn new() -> Self {
        let parser = Parser::new();
        Self { parser }
    }

    pub fn analyze(
        &mut self,
        content: &str,
        path: &Path,
    ) -> Result<(Vec<Finding>, ComplexityMetrics)> {
        let mut findings = Vec::new();
        let mut metrics = ComplexityMetrics {
            cyclomatic_complexity: 0.0,
            duplication_ratio: 0.0,
            function_count: 0,
            max_function_complexity: 0,
        };

        // Set language based on file extension
        let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        match extension {
            "go" => self.parser.set_language(tree_sitter_go::language())
                .map_err(|e| crate::ChainGuardError::Parse(format!("Failed to set Go language: {}", e)))?,
            // TODO: Re-enable Rust support once tree-sitter version conflict is resolved
            // "rs" => self.parser.set_language(tree_sitter_rust::language())
            //     .map_err(|e| crate::ChainGuardError::Parse(format!("Failed to set Rust language: {}", e)))?,
            "js" | "ts" => self.parser.set_language(tree_sitter_javascript::language())
                .map_err(|e| crate::ChainGuardError::Parse(format!("Failed to set JavaScript language: {}", e)))?,
            _ => return Ok((findings, metrics)), // Skip unsupported files
        }

        // Parse the code
        let tree = self
            .parser
            .parse(content, None)
            .ok_or_else(|| crate::ChainGuardError::Parse(format!("Failed to parse {} code", extension)))?;

        // Analyze functions
        self.analyze_functions(
            &tree.root_node(),
            content,
            path,
            &mut findings,
            &mut metrics,
        );

        // Detect code duplication
        let duplication = self.detect_duplication(content);
        metrics.duplication_ratio = duplication.ratio;
        for dup in duplication.findings {
            findings.push(dup);
        }

        // Calculate average complexity
        if metrics.function_count > 0 {
            metrics.cyclomatic_complexity /= metrics.function_count as f64;
        }

        Ok((findings, metrics))
    }

    fn analyze_functions(
        &self,
        node: &Node,
        content: &str,
        path: &Path,
        findings: &mut Vec<Finding>,
        metrics: &mut ComplexityMetrics,
    ) {
        // Support function detection for multiple languages
        let is_function = match node.kind() {
            "function_declaration" | "method_declaration" => true, // Go
            "function_item" => true, // Rust
            "method_definition" => true, // JavaScript/TypeScript (function_declaration already covered above)
            _ => false,
        };
        
        if is_function {
            let complexity = self.calculate_cyclomatic_complexity(node, content);
            metrics.function_count += 1;
            metrics.cyclomatic_complexity += complexity as f64;
            metrics.max_function_complexity = metrics.max_function_complexity.max(complexity);

            // Get function name
            let name_node = node.child_by_field_name("name");
            let function_name = name_node
                .and_then(|n| n.utf8_text(content.as_bytes()).ok())
                .unwrap_or("anonymous");

            // Check complexity thresholds
            if complexity > 15 {
                let start = node.start_position();
                findings.push(Finding {
                    id: "COMPLEX-CYCLOMATIC-HIGH".to_string(),
                    severity: Severity::High,
                    category: "complexity/cyclomatic".to_string(),
                    title: format!("High cyclomatic complexity in function '{}'", function_name),
                    description: format!("Function has cyclomatic complexity of {}, which exceeds recommended threshold of 15", complexity),
                    file: path.display().to_string(),
                    line: start.row + 1,
                    column: start.column,
                    code_snippet: Some(self.extract_function_snippet(node, content)),
                    remediation: Some("Refactor function into smaller, more focused functions".to_string()),
                    references: vec![
                        "https://en.wikipedia.org/wiki/Cyclomatic_complexity".to_string()
                    ],
                    ai_consensus: None,
                });
            } else if complexity > 10 {
                let start = node.start_position();
                findings.push(Finding {
                    id: "COMPLEX-CYCLOMATIC-MEDIUM".to_string(),
                    severity: Severity::Medium,
                    category: "complexity/cyclomatic".to_string(),
                    title: format!(
                        "Moderate cyclomatic complexity in function '{}'",
                        function_name
                    ),
                    description: format!("Function has cyclomatic complexity of {}", complexity),
                    file: path.display().to_string(),
                    line: start.row + 1,
                    column: start.column,
                    code_snippet: None,
                    remediation: Some("Consider simplifying the function logic".to_string()),
                    references: vec![],
                    ai_consensus: None,
                });
            }

            // Check for dead code
            self.check_dead_code(node, content, path, findings);
        }

        // Recurse through children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.analyze_functions(&child, content, path, findings, metrics);
        }
    }

    fn calculate_cyclomatic_complexity(&self, node: &Node, content: &str) -> usize {
        let mut complexity = 1; // Base complexity

        fn count_node_complexity(node: &Node, content_bytes: &[u8]) -> usize {
            let mut local_complexity = 0;

            match node.kind() {
                // Go control flow
                "if_statement"
                | "for_statement"
                | "range_statement"
                | "switch_statement"
                | "type_switch_statement" => {
                    local_complexity += 1;
                }
                // Rust control flow
                "if_expression"
                | "while_expression"
                | "for_expression"
                | "loop_expression"
                | "match_expression" => {
                    local_complexity += 1;
                }
                // Case/match arms
                "case_clause" | "match_arm" => {
                    local_complexity += 1;
                }
                // Binary expressions
                "binary_expression" => {
                    if let Some(child) = node.child(1) {
                        if let Ok(operator) = child.utf8_text(content_bytes) {
                            if operator == "&&" || operator == "||" {
                                local_complexity += 1;
                            }
                        }
                    }
                }
                _ => {}
            }

            // Count complexity of all children
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                local_complexity += count_node_complexity(&child, content_bytes);
            }

            local_complexity
        }

        complexity + count_node_complexity(node, content.as_bytes())
    }

    fn check_dead_code(
        &self,
        node: &Node,
        content: &str,
        path: &Path,
        findings: &mut Vec<Finding>,
    ) {
        // Check for unreachable code after return statements
        let mut cursor = node.walk();
        let mut found_return = false;

        for child in node.children(&mut cursor) {
            if found_return && child.kind() != "comment" {
                let start = child.start_position();
                findings.push(Finding {
                    id: "COMPLEX-DEAD-CODE".to_string(),
                    severity: Severity::Medium,
                    category: "complexity/dead-code".to_string(),
                    title: "Unreachable code detected".to_string(),
                    description: "Code after return statement will never be executed".to_string(),
                    file: path.display().to_string(),
                    line: start.row + 1,
                    column: start.column,
                    code_snippet: Some(
                        child
                            .utf8_text(content.as_bytes())
                            .unwrap_or("")
                            .to_string(),
                    ),
                    remediation: Some("Remove unreachable code".to_string()),
                    references: vec![],
                    ai_consensus: None,
                });
            }

            if child.kind() == "return_statement" || child.kind() == "return_expression" {
                found_return = true;
            }
        }
    }

    fn detect_duplication(&self, content: &str) -> DuplicationResult {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        let mut duplicates = std::collections::HashMap::new();

        // Simple line-based duplication detection
        for i in 0..lines.len() {
            let window_size = 5; // Minimum duplicate block size
            if i + window_size > lines.len() {
                continue;
            }

            let block: Vec<&str> = lines[i..i + window_size].to_vec();
            let block_str = block.join("\n");

            // Skip small or trivial blocks
            if block_str.len() < 50 || block_str.trim().is_empty() {
                continue;
            }

            duplicates
                .entry(block_str.clone())
                .or_insert_with(Vec::new)
                .push(i + 1);
        }

        let total_duplicate_lines = duplicates
            .values()
            .filter(|locations| locations.len() > 1)
            .map(|locations| locations.len() * 5)
            .sum::<usize>();

        let ratio = total_duplicate_lines as f64 / lines.len() as f64;

        for (block, locations) in duplicates {
            if locations.len() > 1 {
                findings.push(Finding {
                    id: "COMPLEX-DUPLICATION".to_string(),
                    severity: Severity::Low,
                    category: "complexity/duplication".to_string(),
                    title: "Code duplication detected".to_string(),
                    description: format!(
                        "Similar code block found in {} locations: lines {}",
                        locations.len(),
                        locations
                            .iter()
                            .map(|l| l.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    file: String::new(),
                    line: locations[0],
                    column: 0,
                    code_snippet: Some(block),
                    remediation: Some(
                        "Extract duplicate code into a reusable function".to_string(),
                    ),
                    references: vec![],
                    ai_consensus: None,
                });
            }
        }

        DuplicationResult { findings, ratio }
    }

    fn extract_function_snippet(&self, node: &Node, content: &str) -> String {
        let start_line = node.start_position().row;
        let end_line = node.start_position().row + 5; // Show first 5 lines

        let lines: Vec<&str> = content.lines().collect();
        let snippet_lines = &lines[start_line..end_line.min(lines.len())];

        snippet_lines
            .iter()
            .enumerate()
            .map(|(i, line)| format!("{:4} | {}", start_line + i + 1, line))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

struct DuplicationResult {
    findings: Vec<Finding>,
    ratio: f64,
}
