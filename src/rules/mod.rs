use crate::{Result, ChainGuardError, Finding, Severity};
use std::path::Path;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use regex::Regex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub category: String,
    pub description: String,
    pub severity: crate::Severity,
    pub enabled: bool,
    pub pattern: Option<String>,
    pub custom: bool,
}

pub struct RuleManager {
    rules: HashMap<String, Rule>,
    custom_rules: HashMap<String, Rule>,
}

impl RuleManager {
    pub fn new() -> Result<Self> {
        let mut manager = Self {
            rules: HashMap::new(),
            custom_rules: HashMap::new(),
        };
        
        manager.load_default_rules();
        Ok(manager)
    }
    
    pub fn list_rules(&self, category: Option<&str>, all: bool) -> Result<Vec<Rule>> {
        let mut rules: Vec<Rule> = self.rules.values()
            .chain(self.custom_rules.values())
            .filter(|r| {
                let category_match = category.map_or(true, |c| r.category.to_lowercase().contains(&c.to_lowercase()));
                let enabled_match = all || r.enabled;
                category_match && enabled_match
            })
            .cloned()
            .collect();
        
        rules.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(rules)
    }
    
    pub fn enable_rule(&mut self, pattern: &str) -> Result<usize> {
        let regex = Regex::new(pattern)
            .map_err(|e| ChainGuardError::Config(format!("Invalid pattern: {}", e)))?;
        
        let mut count = 0;
        
        for rule in self.rules.values_mut() {
            if regex.is_match(&rule.id) {
                rule.enabled = true;
                count += 1;
            }
        }
        
        for rule in self.custom_rules.values_mut() {
            if regex.is_match(&rule.id) {
                rule.enabled = true;
                count += 1;
            }
        }
        
        Ok(count)
    }
    
    pub fn disable_rule(&mut self, pattern: &str) -> Result<usize> {
        let regex = Regex::new(pattern)
            .map_err(|e| ChainGuardError::Config(format!("Invalid pattern: {}", e)))?;
        
        let mut count = 0;
        
        for rule in self.rules.values_mut() {
            if regex.is_match(&rule.id) {
                rule.enabled = false;
                count += 1;
            }
        }
        
        for rule in self.custom_rules.values_mut() {
            if regex.is_match(&rule.id) {
                rule.enabled = false;
                count += 1;
            }
        }
        
        Ok(count)
    }
    
    pub fn import_rules(&mut self, path: &Path) -> Result<usize> {
        let content = std::fs::read_to_string(path)?;
        let imported_rules: Vec<Rule> = if path.extension().map_or(false, |e| e == "yaml" || e == "yml") {
            serde_yaml::from_str(&content)
                .map_err(|e| ChainGuardError::Config(format!("Failed to parse rules YAML: {}", e)))?
        } else {
            serde_json::from_str(&content)
                .map_err(|e| ChainGuardError::Config(format!("Failed to parse rules JSON: {}", e)))?
        };
        
        let count = imported_rules.len();
        for mut rule in imported_rules {
            rule.custom = true;
            self.custom_rules.insert(rule.id.clone(), rule);
        }
        
        Ok(count)
    }
    
    pub fn export_rules(&self, path: &Path, custom_only: bool) -> Result<()> {
        let rules: Vec<Rule> = if custom_only {
            self.custom_rules.values().cloned().collect()
        } else {
            self.rules.values()
                .chain(self.custom_rules.values())
                .cloned()
                .collect()
        };
        
        let content = if path.extension().map_or(false, |e| e == "yaml" || e == "yml") {
            serde_yaml::to_string(&rules)
                .map_err(|e| ChainGuardError::Config(format!("Failed to serialize rules to YAML: {}", e)))?
        } else {
            serde_json::to_string_pretty(&rules)
                .map_err(|e| ChainGuardError::Config(format!("Failed to serialize rules to JSON: {}", e)))?
        };
        
        std::fs::write(path, content)?;
        Ok(())
    }
    
    pub fn validate_rules_file(&self, path: &Path) -> Result<()> {
        let content = std::fs::read_to_string(path)?;
        
        // Try to parse as YAML or JSON
        if path.extension().map_or(false, |e| e == "yaml" || e == "yml") {
            let _: Vec<Rule> = serde_yaml::from_str(&content)
                .map_err(|e| ChainGuardError::Config(format!("Invalid rules YAML: {}", e)))?;
        } else {
            let _: Vec<Rule> = serde_json::from_str(&content)
                .map_err(|e| ChainGuardError::Config(format!("Invalid rules JSON: {}", e)))?;
        }
        
        Ok(())
    }
    
    fn load_default_rules(&mut self) {
        // Security rules
        self.add_rule(Rule {
            id: "FABRIC-SEC-001".to_string(),
            category: "security".to_string(),
            description: "Detect nondeterministic operations".to_string(),
            severity: Severity::Critical,
            enabled: true,
            pattern: Some(r"time\.Now\(\)|rand\.|math/rand".to_string()),
            custom: false,
        });
        
        self.add_rule(Rule {
            id: "FABRIC-SEC-002".to_string(),
            category: "security".to_string(),
            description: "Detect global variable usage".to_string(),
            severity: Severity::High,
            enabled: true,
            pattern: Some(r"var\s+\w+\s+=".to_string()),
            custom: false,
        });
        
        self.add_rule(Rule {
            id: "FABRIC-SEC-003".to_string(),
            category: "security".to_string(),
            description: "Detect private data leakage".to_string(),
            severity: Severity::Critical,
            enabled: true,
            pattern: Some(r"GetPrivateData.*PutState".to_string()),
            custom: false,
        });
        
        // Performance rules
        self.add_rule(Rule {
            id: "FABRIC-PERF-001".to_string(),
            category: "performance".to_string(),
            description: "Detect inefficient rich queries".to_string(),
            severity: Severity::Medium,
            enabled: true,
            pattern: Some(r"GetQueryResult\(|GetQueryResultWithPagination\(".to_string()),
            custom: false,
        });
        
        self.add_rule(Rule {
            id: "FABRIC-PERF-002".to_string(),
            category: "performance".to_string(),
            description: "Detect unbounded loops".to_string(),
            severity: Severity::High,
            enabled: true,
            pattern: Some(r"for\s*\{|while\s*\(".to_string()),
            custom: false,
        });
        
        // Compliance rules
        self.add_rule(Rule {
            id: "FABRIC-COMP-001".to_string(),
            category: "compliance".to_string(),
            description: "Missing access control validation".to_string(),
            severity: Severity::High,
            enabled: true,
            pattern: None,
            custom: false,
        });
        
        // Quality rules
        self.add_rule(Rule {
            id: "FABRIC-QUAL-001".to_string(),
            category: "quality".to_string(),
            description: "Complex function detected".to_string(),
            severity: Severity::Low,
            enabled: true,
            pattern: None,
            custom: false,
        });
        
        // Token standard rules
        self.add_rule(Rule {
            id: "TOKEN-SEC-001".to_string(),
            category: "security".to_string(),
            description: "Missing overflow protection in token arithmetic".to_string(),
            severity: Severity::High,
            enabled: true,
            pattern: Some(r"\+|\-|\*|\/(?!.*SafeMath)".to_string()),
            custom: false,
        });
    }
    
    fn add_rule(&mut self, rule: Rule) {
        self.rules.insert(rule.id.clone(), rule);
    }
    
    pub fn get_enabled_rules(&self) -> Vec<&Rule> {
        self.rules.values()
            .chain(self.custom_rules.values())
            .filter(|r| r.enabled)
            .collect()
    }
    
    pub fn apply_rules(&self, content: &str, file_path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for rule in self.get_enabled_rules() {
            if let Some(pattern) = &rule.pattern {
                if let Ok(regex) = Regex::new(pattern) {
                    for mat in regex.find_iter(content) {
                        let line = content[..mat.start()].lines().count();
                        let column = mat.start() - content[..mat.start()].rfind('\n').unwrap_or(0);
                        
                        findings.push(Finding {
                            id: rule.id.clone(),
                            severity: rule.severity,
                            category: format!("Rules/{}", rule.category),
                            title: rule.description.clone(),
                            description: format!("Rule {} triggered at {}:{}", rule.id, line, column),
                            file: file_path.to_string(),
                            line,
                            column,
                            code_snippet: None,
                            remediation: None,
                            references: vec![],
                            confidence: 0.9,
                            ai_consensus: None,
                        });
                    }
                }
            }
        }
        
        findings
    }
} 