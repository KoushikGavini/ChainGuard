use crate::{Finding, Result, Severity};
use std::path::Path;
use regex::Regex;

pub struct SlopsquattingDetector {
    import_regex: Regex,
    known_packages: Vec<(String, Vec<String>)>,
}

impl SlopsquattingDetector {
    pub fn new() -> Self {
        let import_regex = Regex::new(r#"import\s*(?:\(([^)]+)\)|"([^"]+)")"#).unwrap();
        
        // Known packages and their common misspellings/variations
        let known_packages = vec![
            (
                "github.com/hyperledger/fabric-chaincode-go".to_string(),
                vec![
                    "github.com/hyperledger/fabric-chaincоde-go".to_string(), // Cyrillic 'o'
                    "github.com/hyperledger/fabric-chaincode-g0".to_string(), // Zero instead of 'o'
                    "github.com/hyperledger/fabric-chainc0de-go".to_string(), // Zero in 'code'
                    "github.com/hyperledger/fabrik-chaincode-go".to_string(), // 'k' instead of 'c'
                    "github.com/hyperleger/fabric-chaincode-go".to_string(),  // Missing 'd'
                    "github.com/hyperledge/fabric-chaincode-go".to_string(),  // Missing 'r'
                ]
            ),
            (
                "github.com/hyperledger/fabric-protos-go".to_string(),
                vec![
                    "github.com/hyperledger/fabric-protоs-go".to_string(),    // Cyrillic 'o'
                    "github.com/hyperledger/fabric-protos-g0".to_string(),    // Zero instead of 'o'
                    "github.com/hyperledger/fabric-pr0tos-go".to_string(),    // Zero in 'protos'
                ]
            ),
            (
                "github.com/golang/protobuf".to_string(),
                vec![
                    "github.com/golang/protоbuf".to_string(),                 // Cyrillic 'o'
                    "github.com/golang/pr0tobuf".to_string(),                 // Zero instead of 'o'
                    "github.com/golang/protobuff".to_string(),                // Extra 'f'
                    "github.com/goland/protobuf".to_string(),                 // Missing 'g'
                ]
            ),
        ];
        
        Self {
            import_regex,
            known_packages,
        }
    }

    pub fn detect(&self, content: &str, path: &Path) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Extract imports
        let imports = self.extract_imports(content);
        
        // Check each import for slopsquatting
        for import in &imports {
            // Check against known packages
            for (legitimate, variations) in &self.known_packages {
                if variations.contains(import) {
                    findings.push(Finding {
                        id: "SLOPSQUAT-KNOWN".to_string(),
                        severity: Severity::Critical,
                        category: "validation/slopsquatting".to_string(),
                        title: "Slopsquatting attack detected".to_string(),
                        description: format!(
                            "Import '{}' is a malicious variation of legitimate package '{}'",
                            import, legitimate
                        ),
                        file: path.display().to_string(),
                        line: 0,
                        column: 0,
                        code_snippet: None,
                        remediation: Some(format!("Replace with legitimate package: {}", legitimate)),
                        references: vec![
                            "https://snyk.io/blog/typosquatting-attacks/".to_string()
                        ],
                        ai_consensus: None,
                    });
                }
            }
            
            // Check for homograph attacks
            if self.contains_homographs(import) {
                findings.push(Finding {
                    id: "SLOPSQUAT-HOMOGRAPH".to_string(),
                    severity: Severity::Critical,
                    category: "validation/slopsquatting".to_string(),
                    title: "Homograph attack detected".to_string(),
                    description: format!(
                        "Import '{}' contains visually similar characters that may be malicious",
                        import
                    ),
                    file: path.display().to_string(),
                    line: 0,
                    column: 0,
                    code_snippet: None,
                    remediation: Some("Verify the exact characters in the import path".to_string()),
                    references: vec![
                        "https://en.wikipedia.org/wiki/IDN_homograph_attack".to_string()
                    ],
                    ai_consensus: None,
                });
            }
            
            // Check for suspicious variations
            if self.is_suspicious_variation(import) {
                findings.push(Finding {
                    id: "SLOPSQUAT-SUSPICIOUS".to_string(),
                    severity: Severity::High,
                    category: "validation/slopsquatting".to_string(),
                    title: "Suspicious package name variation".to_string(),
                    description: format!(
                        "Import '{}' appears to be a variation of a known package",
                        import
                    ),
                    file: path.display().to_string(),
                    line: 0,
                    column: 0,
                    code_snippet: None,
                    remediation: Some("Verify this is the intended package".to_string()),
                    references: vec![],
                    ai_consensus: None,
                });
            }
        }
        
        Ok(findings)
    }

    fn extract_imports(&self, content: &str) -> Vec<String> {
        let mut imports = Vec::new();
        
        for cap in self.import_regex.captures_iter(content) {
            if let Some(multi_import) = cap.get(1) {
                for line in multi_import.as_str().lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && !trimmed.starts_with("//") {
                        let import = trimmed.trim_matches('"').to_string();
                        imports.push(import);
                    }
                }
            } else if let Some(single_import) = cap.get(2) {
                imports.push(single_import.as_str().to_string());
            }
        }
        
        imports
    }

    fn contains_homographs(&self, import: &str) -> bool {
        // Common homograph characters used in attacks
        let homographs = vec![
            ('а', 'a'), // Cyrillic 'a'
            ('е', 'e'), // Cyrillic 'e'
            ('о', 'o'), // Cyrillic 'o'
            ('р', 'p'), // Cyrillic 'p'
            ('с', 'c'), // Cyrillic 'c'
            ('х', 'x'), // Cyrillic 'x'
            ('у', 'y'), // Cyrillic 'y'
            ('0', 'o'), // Zero instead of 'o'
            ('1', 'l'), // One instead of 'l'
            ('1', 'i'), // One instead of 'i'
        ];
        
        for (homograph, _) in homographs {
            if import.contains(homograph) {
                return true;
            }
        }
        
        false
    }

    fn is_suspicious_variation(&self, import: &str) -> bool {
        // Check for common typosquatting patterns
        let suspicious_patterns = vec![
            // Extra characters
            r"hyperledgerr",
            r"fabricc",
            r"chaincodee",
            // Missing characters
            r"hyperldger",
            r"fabrc",
            r"chaincde",
            // Swapped characters
            r"hyperleger",
            r"frabiс",
            r"chanicоde",
            // Similar looking replacements
            r"hyper1edger",
            r"fabr1c",
            r"cha1ncode",
        ];
        
        for pattern in suspicious_patterns {
            if import.contains(pattern) {
                return true;
            }
        }
        
        // Check edit distance from known packages
        for (legitimate, _) in &self.known_packages {
            if self.levenshtein_distance(import, legitimate) <= 2 && import != legitimate {
                return true;
            }
        }
        
        false
    }

    fn levenshtein_distance(&self, s1: &str, s2: &str) -> usize {
        let len1 = s1.chars().count();
        let len2 = s2.chars().count();
        let mut matrix = vec![vec![0; len2 + 1]; len1 + 1];
        
        for i in 0..=len1 {
            matrix[i][0] = i;
        }
        for j in 0..=len2 {
            matrix[0][j] = j;
        }
        
        for (i, c1) in s1.chars().enumerate() {
            for (j, c2) in s2.chars().enumerate() {
                let cost = if c1 == c2 { 0 } else { 1 };
                matrix[i + 1][j + 1] = (matrix[i][j + 1] + 1)
                    .min(matrix[i + 1][j] + 1)
                    .min(matrix[i][j] + cost);
            }
        }
        
        matrix[len1][len2]
    }
} 