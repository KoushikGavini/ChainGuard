use crate::{Result, Finding};

#[derive(Debug, Clone)]
pub struct DeterminismAnalyzer;

impl DeterminismAnalyzer {
    pub fn new() -> Self {
        Self
    }
    
    pub fn analyze(&self, _content: &str, _tree: &tree_sitter::Tree) -> Result<Vec<Finding>> {
        Ok(vec![])
    }
}
