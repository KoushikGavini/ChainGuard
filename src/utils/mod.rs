use std::path::Path;
use regex::Regex;
use crate::{ChainGuardError, Result};

pub fn is_go_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext == "go")
        .unwrap_or(false)
}

pub fn extract_line_context(content: &str, line_number: usize, context_lines: usize) -> String {
    let lines: Vec<&str> = content.lines().collect();
    
    // Handle edge cases
    if lines.is_empty() || line_number == 0 {
        return String::new();
    }
    
    // Convert to 0-based index
    let line_idx = line_number.saturating_sub(1);
    
    // Calculate bounds
    let start = line_idx.saturating_sub(context_lines);
    let end = std::cmp::min(line_idx + context_lines + 1, lines.len());
    
    // Ensure valid range
    if start >= lines.len() {
        return String::new();
    }

    lines[start..end]
        .iter()
        .enumerate()
        .map(|(i, line)| format!("{:4} | {}", start + i + 1, line))
        .collect::<Vec<_>>()
        .join("\n")
}

// Convenience function for getting code snippets with default context
pub fn get_code_snippet(content: &str, line: usize) -> String {
    extract_line_context(content, line, 2)
}

// Safe regex creation with proper error handling
pub fn create_regex(pattern: &str) -> Result<Regex> {
    Regex::new(pattern)
        .map_err(|e| ChainGuardError::Parse(format!("Invalid regex pattern '{}': {}", pattern, e)))
}

// Create regex that should never fail - panics in debug mode, returns None in release
pub fn create_static_regex(pattern: &str) -> Option<Regex> {
    match Regex::new(pattern) {
        Ok(regex) => Some(regex),
        Err(e) => {
            #[cfg(debug_assertions)]
            panic!("Static regex '{}' failed to compile: {}", pattern, e);
            
            #[cfg(not(debug_assertions))]
            {
                eprintln!("Warning: Static regex '{}' failed to compile: {}", pattern, e);
                None
            }
        }
    }
}
