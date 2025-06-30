use crate::token_standards::{
    EventParameter, EventSignature, FunctionSignature, Parameter, TokenStandard,
};
use crate::{Finding, Result};

#[derive(Debug, Clone)]
pub struct ERC777Validator;

impl ERC777Validator {
    pub fn new() -> Self {
        Self
    }

    pub fn validate(&self, _content: &str) -> Result<Vec<Finding>> {
        Ok(vec![])
    }
}

impl TokenStandard for ERC777Validator {
    fn validate(&self, code: &str, _language: &str) -> Result<Vec<Finding>> {
        self.validate(code)
    }

    fn name(&self) -> &str {
        "ERC-777"
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
