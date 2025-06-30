use crate::{Finding, Result, Severity};
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;

pub struct DependencyAnalyzer {
    import_regex: Regex,
    external_call_patterns: Vec<ExternalCallPattern>,
}

#[derive(Debug)]
struct ExternalCallPattern {
    name: String,
    regex: Regex,
    severity: Severity,
    description: String,
}

impl DependencyAnalyzer {
    pub fn new() -> Self {
        let import_regex = Regex::new(r#"import\s*(?:\(([^)]+)\)|"([^"]+)")"#).unwrap();

        let external_call_patterns = vec![
            ExternalCallPattern {
                name: "http_client".to_string(),
                regex: Regex::new(r"http\.(Get|Post|Client|Request)").unwrap(),
                severity: Severity::Critical,
                description: "HTTP calls break determinism in chaincode".to_string(),
            },
            ExternalCallPattern {
                name: "database_connection".to_string(),
                regex: Regex::new(r"(sql\.Open|mongo\.Connect|redis\.New)").unwrap(),
                severity: Severity::Critical,
                description: "External database connections are not allowed in chaincode"
                    .to_string(),
            },
            ExternalCallPattern {
                name: "file_operations".to_string(),
                regex: Regex::new(r"(os\.(Open|Create|Remove)|ioutil\.(ReadFile|WriteFile))")
                    .unwrap(),
                severity: Severity::Critical,
                description: "File system operations break determinism".to_string(),
            },
            ExternalCallPattern {
                name: "system_commands".to_string(),
                regex: Regex::new(r"(exec\.Command|os\.Exec|syscall\.)").unwrap(),
                severity: Severity::Critical,
                description: "System command execution is forbidden in chaincode".to_string(),
            },
            ExternalCallPattern {
                name: "network_operations".to_string(),
                regex: Regex::new(r"(net\.(Dial|Listen)|rpc\.|grpc\.)").unwrap(),
                severity: Severity::Critical,
                description: "Network operations violate chaincode isolation".to_string(),
            },
        ];

        Self {
            import_regex,
            external_call_patterns,
        }
    }

    pub fn analyze(&self, content: &str, path: &Path) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Extract and analyze imports
        let imports = self.extract_imports(content);
        self.analyze_imports(&imports, path, &mut findings);

        // Check for external API calls
        for pattern in &self.external_call_patterns {
            for mat in pattern.regex.find_iter(content) {
                let line_number = content[..mat.start()].lines().count();
                findings.push(Finding {
                    id: format!("DEP-EXT-{}", pattern.name.to_uppercase()),
                    severity: pattern.severity,
                    category: "dependencies/external".to_string(),
                    title: format!("External dependency usage: {}", pattern.name),
                    description: pattern.description.clone(),
                    file: path.display().to_string(),
                    line: line_number,
                    column: mat.start() - content.lines().take(line_number - 1).map(|l| l.len() + 1).sum::<usize>(),
                    code_snippet: Some(extract_snippet(content, line_number)),
                    remediation: Some("Remove external dependencies and use chaincode-safe alternatives".to_string()),
                    references: vec![
                        "https://hyperledger-fabric.readthedocs.io/en/latest/chaincode4ade.html#external-dependencies".to_string()
                    ],
                    ai_consensus: None,
                });
            }
        }

        // Check for unsafe package usage
        self.check_unsafe_packages(content, path, &mut findings);

        Ok(findings)
    }

    fn extract_imports(&self, content: &str) -> HashSet<String> {
        let mut imports = HashSet::new();

        for cap in self.import_regex.captures_iter(content) {
            if let Some(multi_import) = cap.get(1) {
                // Multiple imports in parentheses
                for line in multi_import.as_str().lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && !trimmed.starts_with("//") {
                        let import = trimmed.trim_matches('"').to_string();
                        imports.insert(import);
                    }
                }
            } else if let Some(single_import) = cap.get(2) {
                // Single import
                imports.insert(single_import.as_str().to_string());
            }
        }

        imports
    }

    fn analyze_imports(&self, imports: &HashSet<String>, path: &Path, findings: &mut Vec<Finding>) {
        let unsafe_packages = vec![
            ("unsafe", "Unsafe package allows bypassing Go's type safety"),
            (
                "reflect",
                "Reflection can lead to non-deterministic behavior",
            ),
            (
                "plugin",
                "Dynamic plugin loading is not allowed in chaincode",
            ),
            ("cgo", "C bindings are not supported in chaincode"),
            (
                "runtime/debug",
                "Debug package can expose sensitive information",
            ),
        ];

        for (pkg, description) in unsafe_packages {
            if imports.contains(pkg) {
                findings.push(Finding {
                    id: format!("DEP-UNSAFE-{}", pkg.to_uppercase().replace("/", "_")),
                    severity: Severity::High,
                    category: "dependencies/unsafe".to_string(),
                    title: format!("Unsafe package import: {}", pkg),
                    description: description.to_string(),
                    file: path.display().to_string(),
                    line: 0,
                    column: 0,
                    code_snippet: None,
                    remediation: Some(format!("Remove import of '{}' package", pkg)),
                    references: vec![],
                    ai_consensus: None,
                });
            }
        }

        // Check for non-Fabric imports that might be problematic
        for import in imports {
            if !import.starts_with("github.com/hyperledger/fabric")
                && !is_standard_library(import)
                && !is_safe_third_party(import)
            {
                findings.push(Finding {
                    id: "DEP-THIRD-PARTY".to_string(),
                    severity: Severity::Medium,
                    category: "dependencies/third-party".to_string(),
                    title: "Third-party dependency detected".to_string(),
                    description: format!(
                        "External dependency '{}' should be carefully reviewed",
                        import
                    ),
                    file: path.display().to_string(),
                    line: 0,
                    column: 0,
                    code_snippet: None,
                    remediation: Some(
                        "Ensure third-party dependencies are deterministic and secure".to_string(),
                    ),
                    references: vec![],
                    ai_consensus: None,
                });
            }
        }
    }

    fn check_unsafe_packages(&self, content: &str, path: &Path, findings: &mut Vec<Finding>) {
        // Check for common patterns that indicate unsafe operations
        let unsafe_patterns = vec![
            (r"unsafe\.Pointer", "Unsafe pointer manipulation detected"),
            (
                r"reflect\.ValueOf.*\.Pointer\(\)",
                "Unsafe reflection usage",
            ),
            (r"syscall\.", "Direct system call usage"),
            (r"\*\(\*.*\)\(unsafe\.Pointer", "Unsafe type casting"),
        ];

        for (pattern, description) in unsafe_patterns {
            let regex = Regex::new(pattern).unwrap();
            for mat in regex.find_iter(content) {
                let line_number = content[..mat.start()].lines().count();
                findings.push(Finding {
                    id: "DEP-UNSAFE-PATTERN".to_string(),
                    severity: Severity::High,
                    category: "dependencies/unsafe".to_string(),
                    title: "Unsafe code pattern detected".to_string(),
                    description: description.to_string(),
                    file: path.display().to_string(),
                    line: line_number,
                    column: mat.start()
                        - content
                            .lines()
                            .take(line_number - 1)
                            .map(|l| l.len() + 1)
                            .sum::<usize>(),
                    code_snippet: Some(extract_snippet(content, line_number)),
                    remediation: Some("Remove unsafe operations from chaincode".to_string()),
                    references: vec![],
                    ai_consensus: None,
                });
            }
        }
    }
}

fn is_standard_library(import: &str) -> bool {
    let std_packages = vec![
        "fmt",
        "strings",
        "strconv",
        "bytes",
        "errors",
        "encoding/json",
        "encoding/base64",
        "encoding/hex",
        "sort",
        "container/list",
        "math",
        "math/big",
        "time",
        "unicode",
        "unicode/utf8",
    ];

    std_packages
        .iter()
        .any(|&pkg| import == pkg || import.starts_with(&format!("{}/", pkg)))
}

fn is_safe_third_party(import: &str) -> bool {
    // Known safe third-party packages commonly used in chaincode
    let safe_packages = vec!["github.com/golang/protobuf", "google.golang.org/protobuf"];

    safe_packages.iter().any(|&pkg| import.starts_with(pkg))
}

fn extract_snippet(content: &str, line: usize) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let start = line.saturating_sub(2).max(1);
    let end = (line + 2).min(lines.len());

    lines[start - 1..end]
        .iter()
        .enumerate()
        .map(|(i, line)| format!("{:4} | {}", start + i, line))
        .collect::<Vec<_>>()
        .join("\n")
}
