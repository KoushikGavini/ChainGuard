use crate::{Finding, Result, Severity};
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;

pub struct DependencyValidator {
    import_regex: Regex,
    known_vulnerabilities: Vec<VulnerablePackage>,
}

#[derive(Debug)]
struct VulnerablePackage {
    package: String,
    versions: Vec<String>,
    cve: String,
    description: String,
}

impl DependencyValidator {
    pub async fn new() -> Result<Self> {
        let import_regex = Regex::new(r#"import\s*(?:\(([^)]+)\)|"([^"]+)")"#).unwrap();

        // In a real implementation, this would fetch from a vulnerability database
        let known_vulnerabilities = vec![VulnerablePackage {
            package: "github.com/dgrijalva/jwt-go".to_string(),
            versions: vec!["< 4.0.0".to_string()],
            cve: "CVE-2020-26160".to_string(),
            description: "JWT signature validation vulnerability".to_string(),
        }];

        Ok(Self {
            import_regex,
            known_vulnerabilities,
        })
    }

    pub async fn validate(
        &self,
        content: &str,
        path: &Path,
        trusted_packages: &HashSet<String>,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Extract imports
        let imports = self.extract_imports(content);

        // Validate each import
        for import in &imports {
            // Check for hallucinated packages
            if self.is_hallucinated_package(import) {
                findings.push(Finding {
                    id: "DEP-VAL-HALLUCINATED".to_string(),
                    severity: Severity::Critical,
                    category: "validation/dependencies".to_string(),
                    title: "Hallucinated package detected".to_string(),
                    description: format!(
                        "Package '{}' appears to be AI-generated and doesn't exist",
                        import
                    ),
                    file: path.display().to_string(),
                    line: 0,
                    column: 0,
                    code_snippet: None,
                    remediation: Some(
                        "Use valid package names from official repositories".to_string(),
                    ),
                    references: vec![],
                    ai_consensus: None,
                });
            }

            // Check against known vulnerabilities
            for vuln in &self.known_vulnerabilities {
                if import.starts_with(&vuln.package) {
                    findings.push(Finding {
                        id: format!("DEP-VAL-VULN-{}", vuln.cve),
                        severity: Severity::Critical,
                        category: "validation/vulnerability".to_string(),
                        title: format!("Vulnerable dependency: {}", vuln.cve),
                        description: vuln.description.clone(),
                        file: path.display().to_string(),
                        line: 0,
                        column: 0,
                        code_snippet: None,
                        remediation: Some(format!("Update {} to a patched version", vuln.package)),
                        references: vec![vuln.cve.clone()],
                        ai_consensus: None,
                    });
                }
            }

            // Verify package structure
            if !self.is_valid_package_structure(import) {
                findings.push(Finding {
                    id: "DEP-VAL-INVALID-STRUCTURE".to_string(),
                    severity: Severity::Medium,
                    category: "validation/structure".to_string(),
                    title: "Invalid package structure".to_string(),
                    description: format!("Package '{}' has invalid import path structure", import),
                    file: path.display().to_string(),
                    line: 0,
                    column: 0,
                    code_snippet: None,
                    remediation: Some(
                        "Ensure package paths follow Go module conventions".to_string(),
                    ),
                    references: vec![],
                    ai_consensus: None,
                });
            }
        }

        Ok(findings)
    }

    fn extract_imports(&self, content: &str) -> HashSet<String> {
        let mut imports = HashSet::new();

        for cap in self.import_regex.captures_iter(content) {
            if let Some(multi_import) = cap.get(1) {
                for line in multi_import.as_str().lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && !trimmed.starts_with("//") {
                        let import = trimmed.trim_matches('"').to_string();
                        imports.insert(import);
                    }
                }
            } else if let Some(single_import) = cap.get(2) {
                imports.insert(single_import.as_str().to_string());
            }
        }

        imports
    }

    fn is_hallucinated_package(&self, import: &str) -> bool {
        // Check for common AI hallucination patterns
        let hallucination_patterns = vec![
            r"github\.com/hyperledger/fabric-chaincode-go/pkg/\w+", // Wrong structure
            r"github\.com/hyperledger/fabric/pkg/chaincode",        // Doesn't exist
            r"github\.com/fabric/.*",                               // Wrong org
            r"hyperledger\.io/.*",                                  // Wrong domain
        ];

        for pattern in hallucination_patterns {
            if Regex::new(pattern).unwrap().is_match(import) {
                return true;
            }
        }

        false
    }

    fn is_valid_package_structure(&self, import: &str) -> bool {
        // Check if it's a standard library package
        if !import.contains("/") {
            return true;
        }

        // Check for valid domain-based imports
        if import.starts_with("github.com/")
            || import.starts_with("golang.org/")
            || import.starts_with("google.golang.org/")
        {
            // Validate structure: domain/org/repo/...
            let parts: Vec<&str> = import.split('/').collect();
            return parts.len() >= 3;
        }

        // Check for other valid patterns
        if import.contains(".") && import.contains("/") {
            return true;
        }

        false
    }
}
