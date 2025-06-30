// Placeholder module

use crate::{Finding, Result};

#[derive(Debug, Clone)]
pub struct StateDBAnalyzer;

impl StateDBAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, _content: &str, _tree: &tree_sitter::Tree) -> Result<Vec<Finding>> {
        Ok(vec![])
    }
}
