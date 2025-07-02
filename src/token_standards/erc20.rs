use crate::token_standards::{
    EventParameter, EventSignature, FunctionSignature, Parameter, TokenStandard,
};
use crate::{Finding, Result, Severity};
use regex::Regex;

#[derive(Debug, Clone)]
pub struct ERC20Validator;

impl ERC20Validator {
    pub fn new() -> Self {
        Self
    }

    pub fn validate(&self, content: &str) -> Result<Vec<Finding>> {
        let mut findings = vec![];

        // Check for required functions
        for func in self.required_functions() {
            if !self.function_exists(content, &func) {
                findings.push(Finding {
                    id: format!("ERC20-MISSING-{}", func.name.to_uppercase()),
                    severity: Severity::High,
                    category: "token-standards/erc20".to_string(),
                    title: format!("Missing required ERC-20 function: {}", func.name),
                    description: format!(
                        "ERC-20 standard requires implementation of {} function",
                        func.name
                    ),
                    file: String::new(),
                    line: 0,
                    column: 0,
                    code_snippet: None,
                    remediation: Some(format!(
                        "Implement the {} function according to ERC-20 standard",
                        func.name
                    )),
                    references: vec!["https://eips.ethereum.org/EIPS/eip-20".to_string()],
                    ai_consensus: None,
                });
            }
        }

        // Check for required events
        for event in self.required_events() {
            if !self.event_exists(content, &event) {
                findings.push(Finding {
                    id: format!("ERC20-MISSING-EVENT-{}", event.name.to_uppercase()),
                    severity: Severity::High,
                    category: "token-standards/erc20".to_string(),
                    title: format!("Missing required ERC-20 event: {}", event.name),
                    description: format!(
                        "ERC-20 standard requires {} event to be defined",
                        event.name
                    ),
                    file: String::new(),
                    line: 0,
                    column: 0,
                    code_snippet: None,
                    remediation: Some(format!("Define the {} event", event.name)),
                    references: vec!["https://eips.ethereum.org/EIPS/eip-20".to_string()],
                    ai_consensus: None,
                });
            }
        }

        Ok(findings)
    }

    fn function_exists(&self, content: &str, func: &FunctionSignature) -> bool {
        let pattern = format!(r"function\s+{}\s*\(", regex::escape(&func.name));
        match crate::utils::create_regex(&pattern) {
            Ok(regex) => regex.is_match(content),
            Err(_) => false,
        }
    }

    fn event_exists(&self, content: &str, event: &EventSignature) -> bool {
        let pattern = format!(r"event\s+{}\s*\(", regex::escape(&event.name));
        match crate::utils::create_regex(&pattern) {
            Ok(regex) => regex.is_match(content),
            Err(_) => false,
        }
    }
}

impl TokenStandard for ERC20Validator {
    fn validate(&self, code: &str, _language: &str) -> Result<Vec<Finding>> {
        self.validate(code)
    }

    fn name(&self) -> &str {
        "ERC-20"
    }

    fn required_functions(&self) -> Vec<FunctionSignature> {
        vec![
            FunctionSignature {
                name: "totalSupply".to_string(),
                parameters: vec![],
                returns: vec![Parameter {
                    name: "".to_string(),
                    type_: "uint256".to_string(),
                }],
                visibility: "public".to_string(),
                mutability: "view".to_string(),
            },
            FunctionSignature {
                name: "balanceOf".to_string(),
                parameters: vec![Parameter {
                    name: "_owner".to_string(),
                    type_: "address".to_string(),
                }],
                returns: vec![Parameter {
                    name: "balance".to_string(),
                    type_: "uint256".to_string(),
                }],
                visibility: "public".to_string(),
                mutability: "view".to_string(),
            },
            FunctionSignature {
                name: "transfer".to_string(),
                parameters: vec![
                    Parameter {
                        name: "_to".to_string(),
                        type_: "address".to_string(),
                    },
                    Parameter {
                        name: "_value".to_string(),
                        type_: "uint256".to_string(),
                    },
                ],
                returns: vec![Parameter {
                    name: "success".to_string(),
                    type_: "bool".to_string(),
                }],
                visibility: "public".to_string(),
                mutability: "nonpayable".to_string(),
            },
            FunctionSignature {
                name: "transferFrom".to_string(),
                parameters: vec![
                    Parameter {
                        name: "_from".to_string(),
                        type_: "address".to_string(),
                    },
                    Parameter {
                        name: "_to".to_string(),
                        type_: "address".to_string(),
                    },
                    Parameter {
                        name: "_value".to_string(),
                        type_: "uint256".to_string(),
                    },
                ],
                returns: vec![Parameter {
                    name: "success".to_string(),
                    type_: "bool".to_string(),
                }],
                visibility: "public".to_string(),
                mutability: "nonpayable".to_string(),
            },
            FunctionSignature {
                name: "approve".to_string(),
                parameters: vec![
                    Parameter {
                        name: "_spender".to_string(),
                        type_: "address".to_string(),
                    },
                    Parameter {
                        name: "_value".to_string(),
                        type_: "uint256".to_string(),
                    },
                ],
                returns: vec![Parameter {
                    name: "success".to_string(),
                    type_: "bool".to_string(),
                }],
                visibility: "public".to_string(),
                mutability: "nonpayable".to_string(),
            },
            FunctionSignature {
                name: "allowance".to_string(),
                parameters: vec![
                    Parameter {
                        name: "_owner".to_string(),
                        type_: "address".to_string(),
                    },
                    Parameter {
                        name: "_spender".to_string(),
                        type_: "address".to_string(),
                    },
                ],
                returns: vec![Parameter {
                    name: "remaining".to_string(),
                    type_: "uint256".to_string(),
                }],
                visibility: "public".to_string(),
                mutability: "view".to_string(),
            },
        ]
    }

    fn required_events(&self) -> Vec<EventSignature> {
        vec![
            EventSignature {
                name: "Transfer".to_string(),
                parameters: vec![
                    EventParameter {
                        name: "_from".to_string(),
                        type_: "address".to_string(),
                        indexed: true,
                    },
                    EventParameter {
                        name: "_to".to_string(),
                        type_: "address".to_string(),
                        indexed: true,
                    },
                    EventParameter {
                        name: "_value".to_string(),
                        type_: "uint256".to_string(),
                        indexed: false,
                    },
                ],
            },
            EventSignature {
                name: "Approval".to_string(),
                parameters: vec![
                    EventParameter {
                        name: "_owner".to_string(),
                        type_: "address".to_string(),
                        indexed: true,
                    },
                    EventParameter {
                        name: "_spender".to_string(),
                        type_: "address".to_string(),
                        indexed: true,
                    },
                    EventParameter {
                        name: "_value".to_string(),
                        type_: "uint256".to_string(),
                        indexed: false,
                    },
                ],
            },
        ]
    }

    fn optional_functions(&self) -> Vec<FunctionSignature> {
        vec![
            FunctionSignature {
                name: "name".to_string(),
                parameters: vec![],
                returns: vec![Parameter {
                    name: "".to_string(),
                    type_: "string".to_string(),
                }],
                visibility: "public".to_string(),
                mutability: "view".to_string(),
            },
            FunctionSignature {
                name: "symbol".to_string(),
                parameters: vec![],
                returns: vec![Parameter {
                    name: "".to_string(),
                    type_: "string".to_string(),
                }],
                visibility: "public".to_string(),
                mutability: "view".to_string(),
            },
            FunctionSignature {
                name: "decimals".to_string(),
                parameters: vec![],
                returns: vec![Parameter {
                    name: "".to_string(),
                    type_: "uint8".to_string(),
                }],
                visibility: "public".to_string(),
                mutability: "view".to_string(),
            },
        ]
    }
}
