use std::path::Path;

pub fn is_go_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext == "go")
        .unwrap_or(false)
}

pub fn extract_line_context(content: &str, line_number: usize, context_lines: usize) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let start = line_number.saturating_sub(context_lines).max(1);
    let end = (line_number + context_lines).min(lines.len());
    
    lines[start - 1..end]
        .iter()
        .enumerate()
        .map(|(i, line)| format!("{:4} | {}", start + i, line))
        .collect::<Vec<_>>()
        .join("\n")
} 