use crate::{Finding, Result, Severity};
use regex::Regex;
use tree_sitter::Tree;

pub struct SolanaPerformanceAnalyzer;

impl SolanaPerformanceAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, content: &str, _tree: &Tree) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for performance issues
        findings.extend(self.check_excessive_cpi(content)?);
        findings.extend(self.check_inefficient_iterations(content)?);
        findings.extend(self.check_large_account_data(content)?);
        findings.extend(self.check_compute_unit_usage(content)?);
        findings.extend(self.check_excessive_logging(content)?);

        Ok(findings)
    }

    fn check_excessive_cpi(&self, content: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Count CPI invocations
        let cpi_pattern = Regex::new(r"invoke(_signed)?\s*\(").unwrap();
        let cpi_matches: Vec<_> = cpi_pattern.find_iter(content).collect();

        // Check if there are multiple CPIs in close proximity
        for window in cpi_matches.windows(2) {
            let distance = window[1].start() - window[0].end();
            if distance < 200 {
                // CPIs within ~10 lines
                let (line, column) = self.get_line_column(content, window[0].start());

                findings.push(Finding {
                    id: "SOL-PERF-001".to_string(),
                    severity: Severity::Medium,
                    category: "Solana/Performance".to_string(),
                    title: "Multiple CPIs in close proximity".to_string(),
                    description:
                        "Multiple cross-program invocations detected close together. \
                        Consider batching operations to reduce CPI overhead.".to_string(),
                    file: "".to_string(),
                    line,
                    column,
                    code_snippet: Some(self.get_code_snippet(content, line)),
                    remediation: Some(
                        "Batch operations into a single CPI when possible to reduce compute units".to_string()
                    ),
                    references: vec![
                        "https://docs.solana.com/developing/programming-model/runtime#compute-budget".to_string()
                    ],
                    ai_consensus: None,
                });
                break; // Only report once per file
            }
        }

        Ok(findings)
    }

    fn check_inefficient_iterations(&self, content: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for iteration over all accounts
        let iter_patterns = vec![
            (r"accounts\.iter\(\)", "Iterating over all accounts"),
            (r"for.*in.*accounts", "Looping through accounts"),
            (
                r"remaining_accounts\.iter\(\)",
                "Iterating over remaining accounts",
            ),
        ];

        for (pattern, desc) in iter_patterns {
            let regex = Regex::new(pattern).unwrap();

            for mat in regex.find_iter(content) {
                let pos = mat.start();
                let (line, column) = self.get_line_column(content, pos);

                // Check if there's filtering or early exit
                let context = self.get_context_around(content, pos, 300);
                if !context.contains("break")
                    && !context.contains("take(")
                    && !context.contains("filter")
                {
                    findings.push(Finding {
                        id: "SOL-PERF-002".to_string(),
                        severity: Severity::Medium,
                        category: "Solana/Performance".to_string(),
                        title: format!("{} without optimization", desc),
                        description: format!(
                            "{} without apparent filtering or early exit. \
                            This could consume excessive compute units.",
                            desc
                        ),
                        file: "".to_string(),
                        line,
                        column,
                        code_snippet: Some(self.get_code_snippet(content, line)),
                        remediation: Some(
                            "Add filtering, use iterators efficiently, or implement early exit conditions".to_string()
                        ),
                        references: vec![],
                        ai_consensus: None,
                    });
                }
            }
        }

        Ok(findings)
    }

    fn check_large_account_data(&self, content: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for large data operations
        let data_patterns = vec![
            (r"vec!\[.*;\s*(\d+)\s*\]", "Large vector allocation"),
            (r"Box::new\(\[.*;\s*(\d+)\s*\]\)", "Large array allocation"),
            (r"resize\s*\(\s*(\d+)", "Vector resize operation"),
        ];

        for (pattern, desc) in data_patterns {
            let regex = Regex::new(pattern).unwrap();

            for mat in regex.find_iter(content) {
                // Try to extract the size
                if let Some(size_match) = regex.captures_at(content, mat.start()) {
                    if let Some(size_str) = size_match.get(1) {
                        if let Ok(size) = size_str.as_str().parse::<usize>() {
                            if size > 1000 {
                                // Arbitrary threshold
                                let pos = mat.start();
                                let (line, column) = self.get_line_column(content, pos);

                                findings.push(Finding {
                                    id: "SOL-PERF-003".to_string(),
                                    severity: Severity::Low,
                                    category: "Solana/Performance".to_string(),
                                    title: desc.to_string(),
                                    description: format!(
                                        "Large data allocation of {} elements detected. \
                                        This could impact transaction size and compute units.",
                                        size
                                    ),
                                    file: "".to_string(),
                                    line,
                                    column,
                                    code_snippet: Some(self.get_code_snippet(content, line)),
                                    remediation: Some(
                                        "Consider using smaller data structures or paginating large datasets".to_string()
                                    ),
                                    references: vec![],
                                    ai_consensus: None,
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    fn check_compute_unit_usage(&self, content: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for expensive operations
        let expensive_ops = vec![
            (r"syscall::", "System call usage"),
            (r"sha256|keccak|blake3", "Cryptographic hash function"),
            (r"ed25519|secp256k1", "Elliptic curve operations"),
        ];

        for (pattern, desc) in expensive_ops {
            let regex = Regex::new(pattern).unwrap();
            let matches: Vec<_> = regex.find_iter(content).collect();

            if matches.len() > 3 {
                // Multiple expensive operations
                let (line, _) = self.get_line_column(content, matches[0].start());

                findings.push(Finding {
                    id: "SOL-PERF-004".to_string(),
                    severity: Severity::Low,
                    category: "Solana/Performance".to_string(),
                    title: format!("Multiple {} detected", desc),
                    description: format!(
                        "Found {} instances of {}. These operations consume significant compute units.",
                        matches.len(),
                        desc
                    ),
                    file: "".to_string(),
                    line,
                    column: 1,
                    code_snippet: Some(self.get_code_snippet(content, line)),
                    remediation: Some(
                        "Consider caching results or optimizing the number of expensive operations".to_string()
                    ),
                    references: vec![
                        "https://docs.solana.com/developing/programming-model/runtime#compute-budget".to_string()
                    ],
                    ai_consensus: None,
                });
            }
        }

        Ok(findings)
    }

    fn check_excessive_logging(&self, content: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for excessive logging
        let log_patterns = vec![r"msg!", r"sol_log", r"println!", r"eprintln!"];

        let mut total_logs = 0;
        for pattern in log_patterns {
            let regex = Regex::new(pattern).unwrap();
            total_logs += regex.find_iter(content).count();
        }

        if total_logs > 10 {
            // Arbitrary threshold
            findings.push(Finding {
                id: "SOL-PERF-005".to_string(),
                severity: Severity::Low,
                category: "Solana/Performance".to_string(),
                title: "Excessive logging detected".to_string(),
                description: format!(
                    "Found {} log statements. Excessive logging consumes compute units and should be minimized in production.",
                    total_logs
                ),
                file: "".to_string(),
                line: 1,
                column: 1,
                code_snippet: None,
                remediation: Some(
                    "Remove or reduce logging in production code. Use conditional compilation for debug logs".to_string()
                ),
                references: vec![],
                ai_consensus: None,
            });
        }

        Ok(findings)
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
        let start = if pos > context_size {
            pos - context_size
        } else {
            0
        };
        let end = std::cmp::min(pos + context_size, content.len());
        content[start..end].to_string()
    }
}
