use crate::{Finding, Result};

#[derive(Debug, Clone)]
pub struct FabricPerformanceAnalyzer;

impl FabricPerformanceAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, _content: &str, _tree: &tree_sitter::Tree) -> Result<Vec<Finding>> {
        Ok(vec![])
    }
}
