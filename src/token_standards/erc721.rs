use crate::token_standards::{
    EventParameter, EventSignature, FunctionSignature, Parameter, TokenStandard,
};
use crate::{Finding, Result};

#[derive(Debug, Clone)]
pub struct ERC721Validator;

impl ERC721Validator {
    pub fn new() -> Self {
        Self
    }

    pub fn validate(&self, _content: &str) -> Result<Vec<Finding>> {
        Ok(vec![])
    }
}

impl TokenStandard for ERC721Validator {
    fn validate(&self, code: &str, _language: &str) -> Result<Vec<Finding>> {
        self.validate(code)
    }

    fn name(&self) -> &str {
        "ERC-721"
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
