use crate::{ShieldContractError, Finding, Result, Severity};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod erc1155;
pub mod erc20;
pub mod erc721;
pub mod erc777;
pub mod stablecoin;

pub struct TokenStandardsValidator {
    erc20_validator: erc20::ERC20Validator,
    erc721_validator: erc721::ERC721Validator,
    erc1155_validator: erc1155::ERC1155Validator,
    erc777_validator: erc777::ERC777Validator,
    stablecoin_validator: stablecoin::StablecoinValidator,
    loaded_standards: HashMap<String, Box<dyn TokenStandard>>,
}

pub trait TokenStandard: Send + Sync {
    fn validate(&self, code: &str, language: &str) -> Result<Vec<Finding>>;
    fn name(&self) -> &str;
    fn required_functions(&self) -> Vec<FunctionSignature>;
    fn required_events(&self) -> Vec<EventSignature>;
    fn optional_functions(&self) -> Vec<FunctionSignature>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSignature {
    pub name: String,
    pub parameters: Vec<Parameter>,
    pub returns: Vec<Parameter>,
    pub visibility: String,
    pub mutability: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSignature {
    pub name: String,
    pub parameters: Vec<EventParameter>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub type_: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventParameter {
    pub name: String,
    pub type_: String,
    pub indexed: bool,
}

impl TokenStandardsValidator {
    pub fn new() -> Self {
        Self {
            erc20_validator: erc20::ERC20Validator::new(),
            erc721_validator: erc721::ERC721Validator::new(),
            erc1155_validator: erc1155::ERC1155Validator::new(),
            erc777_validator: erc777::ERC777Validator::new(),
            stablecoin_validator: stablecoin::StablecoinValidator::new(),
            loaded_standards: HashMap::new(),
        }
    }

    pub fn load_standard(&mut self, standard: &str) -> Result<()> {
        let validator: Box<dyn TokenStandard> = match standard.to_lowercase().as_str() {
            "erc20" | "erc-20" => Box::new(self.erc20_validator.clone()),
            "erc721" | "erc-721" => Box::new(self.erc721_validator.clone()),
            "erc1155" | "erc-1155" => Box::new(self.erc1155_validator.clone()),
            "erc777" | "erc-777" => Box::new(self.erc777_validator.clone()),
            "stablecoin" | "stable" => Box::new(self.stablecoin_validator.clone()),
            _ => {
                return Err(ShieldContractError::TokenStandard(format!(
                    "Unknown token standard: {}",
                    standard
                )))
            }
        };

        self.loaded_standards
            .insert(standard.to_string(), validator);
        Ok(())
    }

    pub async fn validate_contract(
        &self,
        code: &str,
        language: &str,
    ) -> Result<TokenValidationResult> {
        let mut all_findings = Vec::new();
        let mut compliance_results = HashMap::new();

        for (standard_name, validator) in &self.loaded_standards {
            let findings = validator.validate(code, language)?;
            let compliance = self.calculate_compliance(&findings, validator.as_ref());

            compliance_results.insert(standard_name.clone(), compliance);
            all_findings.extend(findings);
        }

        Ok(TokenValidationResult {
            findings: all_findings,
            compliance_results: compliance_results.clone(),
            overall_score: self.calculate_overall_score(&compliance_results),
        })
    }

    pub fn validate_fabric_token(&self, code: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Adapt ERC standards for Hyperledger Fabric
        findings.extend(self.check_fabric_token_functions(code)?);
        findings.extend(self.check_fabric_token_events(code)?);
        findings.extend(self.check_fabric_token_security(code)?);

        Ok(findings)
    }

    fn check_fabric_token_functions(&self, code: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Essential token functions adapted for Fabric
        let required_functions = vec![
            ("Transfer", "Transfer tokens between accounts"),
            ("BalanceOf", "Query token balance"),
            ("TotalSupply", "Get total token supply"),
            ("Approve", "Approve spending allowance"),
            ("Allowance", "Query spending allowance"),
            ("TransferFrom", "Transfer on behalf of another account"),
        ];

        for (func_name, description) in required_functions {
            if !code.contains(&format!("func {}", func_name)) && !code.contains(&format!("func ("))
            {
                findings.push(Finding {
                    id: format!("TOKEN-FABRIC-001"),
                    severity: Severity::High,
                    category: "TokenStandard/Fabric".to_string(),
                    title: format!("Missing required token function: {}", func_name),
                    description: format!(
                        "Token contract is missing the '{}' function. {}",
                        func_name, description
                    ),
                    file: "".to_string(),
                    line: 1,
                    column: 1,
                    code_snippet: None,
                    remediation: Some(format!(
                        "Implement the {} function according to token standards",
                        func_name
                    )),
                    references: vec![],
                    ai_consensus: None,
                });
            }
        }

        Ok(findings)
    }

    fn check_fabric_token_events(&self, code: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for event emission
        let required_events = vec![
            ("Transfer", "SetEvent.*Transfer"),
            ("Approval", "SetEvent.*Approval"),
        ];

        for (event_name, pattern) in required_events {
            let regex = Regex::new(pattern).unwrap();
            if !regex.is_match(code) {
                findings.push(Finding {
                    id: format!("TOKEN-EVENT-001"),
                    severity: Severity::Medium,
                    category: "TokenStandard/Events".to_string(),
                    title: format!("Missing event emission: {}", event_name),
                    description: format!(
                        "Token contract does not emit '{}' event. Events are crucial for \
                        client applications to track token movements.",
                        event_name
                    ),
                    file: "".to_string(),
                    line: 1,
                    column: 1,
                    code_snippet: None,
                    remediation: Some(format!("Use stub.SetEvent() to emit {} events", event_name)),
                    references: vec![],
                    ai_consensus: None,
                });
            }
        }

        Ok(findings)
    }

    fn check_fabric_token_security(&self, code: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for integer overflow protection
        if !code.contains("SafeMath") && !code.contains("overflow") {
            findings.push(Finding {
                id: "TOKEN-SEC-001".to_string(),
                severity: Severity::High,
                category: "TokenStandard/Security".to_string(),
                title: "Missing overflow protection".to_string(),
                description: "Token arithmetic operations lack overflow protection. \
                    This could lead to critical vulnerabilities."
                    .to_string(),
                file: "".to_string(),
                line: 1,
                column: 1,
                code_snippet: None,
                remediation: Some(
                    "Implement safe arithmetic operations with overflow checks".to_string(),
                ),
                references: vec![],
                ai_consensus: None,
            });
        }

        // Check for access control
        if !code.contains("GetCreator") && !code.contains("access control") {
            findings.push(Finding {
                id: "TOKEN-SEC-002".to_string(),
                severity: Severity::High,
                category: "TokenStandard/Security".to_string(),
                title: "Missing access control".to_string(),
                description:
                    "Token contract lacks proper access control for privileged operations \
                    like minting or burning."
                        .to_string(),
                file: "".to_string(),
                line: 1,
                column: 1,
                code_snippet: None,
                remediation: Some(
                    "Implement role-based access control for administrative functions".to_string(),
                ),
                references: vec![],
                ai_consensus: None,
            });
        }

        Ok(findings)
    }

    fn calculate_compliance(
        &self,
        findings: &[Finding],
        standard: &dyn TokenStandard,
    ) -> ComplianceResult {
        let required_functions = standard.required_functions();
        let required_events = standard.required_events();

        let missing_functions = findings
            .iter()
            .filter(|f| f.category.contains("Function"))
            .count();

        let missing_events = findings
            .iter()
            .filter(|f| f.category.contains("Event"))
            .count();

        let total_requirements = required_functions.len() + required_events.len();
        let missing_requirements = missing_functions + missing_events;

        let compliance_score = if total_requirements > 0 {
            ((total_requirements - missing_requirements) as f32 / total_requirements as f32) * 100.0
        } else {
            100.0
        };

        ComplianceResult {
            standard: standard.name().to_string(),
            compliance_score,
            missing_functions,
            missing_events,
            security_issues: findings
                .iter()
                .filter(|f| f.severity >= Severity::High)
                .count(),
        }
    }

    fn calculate_overall_score(
        &self,
        compliance_results: &HashMap<String, ComplianceResult>,
    ) -> f32 {
        if compliance_results.is_empty() {
            return 100.0;
        }

        let total_score: f32 = compliance_results
            .values()
            .map(|r| r.compliance_score)
            .sum();

        total_score / compliance_results.len() as f32
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenValidationResult {
    pub findings: Vec<Finding>,
    pub compliance_results: HashMap<String, ComplianceResult>,
    pub overall_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceResult {
    pub standard: String,
    pub compliance_score: f32,
    pub missing_functions: usize,
    pub missing_events: usize,
    pub security_issues: usize,
}
