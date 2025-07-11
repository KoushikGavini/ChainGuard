use crate::token_standards::{
    EventParameter, EventSignature, FunctionSignature, Parameter, TokenStandard,
};
use crate::{Finding, Result};

#[derive(Debug, Clone)]
pub struct ERC1155Validator;

impl ERC1155Validator {
    pub fn new() -> Self {
        Self
    }

    pub fn validate(&self, _content: &str) -> Result<Vec<Finding>> {
        Ok(vec![])
    }
}

impl TokenStandard for ERC1155Validator {
    fn validate(&self, code: &str, _language: &str) -> Result<Vec<Finding>> {
        self.validate(code)
    }

    fn name(&self) -> &str {
        "ERC-1155"
    }

    fn required_functions(&self) -> Vec<FunctionSignature> {
        vec![]
    }

    fn required_events(&self) -> Vec<EventSignature> {
        vec![]
    }

    fn optional_functions(&self) -> Vec<FunctionSignature> {
        vec![]
    }
}
