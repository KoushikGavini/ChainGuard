pub mod ai_patterns;
pub mod dependency_validator;
pub mod slopsquatting;

use crate::{Finding, Result, Severity};
use std::path::Path;
use std::collections::HashSet;

pub struct Validator {
    ai_validator: ai_patterns::AIPatternValidator,
    dep_validator: dependency_validator::DependencyValidator,
    slopsquatting_detector: slopsquatting::SlopsquattingDetector,
    trusted_packages: HashSet<String>,
}

impl Validator {
    pub async fn new() -> Result<Self> {
        let trusted_packages = Self::load_trusted_packages();
        
        Ok(Self {
            ai_validator: ai_patterns::AIPatternValidator::new(),
            dep_validator: dependency_validator::DependencyValidator::new().await?,
            slopsquatting_detector: slopsquatting::SlopsquattingDetector::new(),
            trusted_packages,
        })
    }

    fn load_trusted_packages() -> HashSet<String> {
        let mut packages = HashSet::new();
        
        // Core Hyperledger Fabric packages
        packages.insert("github.com/hyperledger/fabric-chaincode-go".to_string());
        packages.insert("github.com/hyperledger/fabric-protos-go".to_string());
        packages.insert("github.com/hyperledger/fabric-contract-api-go".to_string());
        packages.insert("github.com/hyperledger/fabric".to_string());
        
        // Standard Go libraries
        packages.insert("fmt".to_string());
        packages.insert("encoding/json".to_string());
        packages.insert("strconv".to_string());
        packages.insert("strings".to_string());
        packages.insert("bytes".to_string());
        packages.insert("errors".to_string());
        
        packages
    }

    pub async fn validate(&self, content: &str, path: &Path) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Validate AI patterns
        let ai_findings = self.ai_validator.validate(content, path)?;
        findings.extend(ai_findings);
        
        // Validate dependencies
        let dep_findings = self.dep_validator.validate(content, path, &self.trusted_packages).await?;
        findings.extend(dep_findings);
        
        // Check for slopsquatting
        let slopsquatting_findings = self.slopsquatting_detector.detect(content, path)?;
        findings.extend(slopsquatting_findings);
        
        Ok(findings)
    }

    pub fn validate_import(&self, import_path: &str) -> Option<Finding> {
        if !self.trusted_packages.contains(import_path) && 
           !import_path.starts_with("github.com/hyperledger/") {
            
            // Check if it's a suspicious variation
            if self.is_suspicious_import(import_path) {
                return Some(Finding {
                    id: "VAL-IMP-SUSPICIOUS".to_string(),
                    severity: Severity::High,
                    category: "validation/imports".to_string(),
                    title: "Suspicious import detected".to_string(),
                    description: format!("Import '{}' appears to be a variation of a trusted package", import_path),
                    file: String::new(),
                    line: 0,
                    column: 0,
                    code_snippet: None,
                    remediation: Some("Verify the import path is correct and from a trusted source".to_string()),
                    references: vec![],
                    ai_consensus: None,
                });
            }
        }
        
        None
    }

    fn is_suspicious_import(&self, import_path: &str) -> bool {
        // Check for common typos and variations
        let suspicious_patterns = vec![
            ("hyperledger", vec!["hyperledge", "hyperleger", "hyperledgerr", "hyperldger"]),
            ("fabric", vec!["fabrik", "fabic", "fabricc", "frabiс"]), // Note: last 'c' is Cyrillic
            ("chaincode", vec!["chaincode", "chaincde", "chainocde", "chaincоde"]), // Note: 'o' is Cyrillic
        ];
        
        for (correct, variations) in suspicious_patterns {
            for variation in variations {
                if import_path.contains(variation) && !import_path.contains(correct) {
                    return true;
                }
            }
        }
        
        false
    }
} 