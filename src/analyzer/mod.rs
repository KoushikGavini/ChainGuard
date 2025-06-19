pub mod security;
pub mod performance;
pub mod complexity;
pub mod dependencies;

use crate::{Finding, Result};
use std::path::Path;
use tokio::fs;
use tracing::{debug, info};

#[derive(Debug)]
pub struct AnalysisResult {
    pub findings: Vec<Finding>,
    pub metrics: AnalysisMetrics,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct AnalysisMetrics {
    pub total_files: usize,
    pub total_lines: usize,
    pub cyclomatic_complexity: f64,
    pub code_duplication_ratio: f64,
    pub security_score: f64,
    pub performance_score: f64,
    pub ai_validation_score: f64,
}

pub struct Analyzer {
    security_analyzer: security::SecurityAnalyzer,
    performance_analyzer: performance::PerformanceAnalyzer,
    complexity_analyzer: complexity::ComplexityAnalyzer,
    dependency_analyzer: dependencies::DependencyAnalyzer,
}

impl Analyzer {
    pub fn new() -> Self {
        Self {
            security_analyzer: security::SecurityAnalyzer::new(),
            performance_analyzer: performance::PerformanceAnalyzer::new(),
            complexity_analyzer: complexity::ComplexityAnalyzer::new(),
            dependency_analyzer: dependencies::DependencyAnalyzer::new(),
        }
    }

    pub async fn analyze_file(&mut self, path: &Path) -> Result<AnalysisResult> {
        info!("Analyzing file: {}", path.display());
        
        let content = fs::read_to_string(path).await?;
        let mut findings = Vec::new();
        let mut metrics = AnalysisMetrics::default();
        
        // Run security analysis
        debug!("Running security analysis");
        let security_findings = self.security_analyzer.analyze(&content, path)?;
        findings.extend(security_findings);
        
        // Run performance analysis
        debug!("Running performance analysis");
        let perf_findings = self.performance_analyzer.analyze(&content, path)?;
        findings.extend(perf_findings);
        
        // Run complexity analysis
        debug!("Running complexity analysis");
        let (complexity_findings, complexity_metrics) = self.complexity_analyzer.analyze(&content, path)?;
        findings.extend(complexity_findings);
        metrics.cyclomatic_complexity = complexity_metrics.cyclomatic_complexity;
        metrics.code_duplication_ratio = complexity_metrics.duplication_ratio;
        
        // Run dependency analysis
        debug!("Running dependency analysis");
        let dep_findings = self.dependency_analyzer.analyze(&content, path)?;
        findings.extend(dep_findings);
        
        // Calculate scores
        metrics.total_lines = content.lines().count();
        metrics.security_score = calculate_security_score(&findings);
        metrics.performance_score = calculate_performance_score(&findings);
        
        Ok(AnalysisResult { findings, metrics })
    }
    
    pub async fn quick_scan(&self, path: &Path) -> Result<AnalysisResult> {
        info!("Quick scanning file: {}", path.display());
        
        let content = fs::read_to_string(path).await?;
        let mut findings = Vec::new();
        let mut metrics = AnalysisMetrics::default();
        
        // Only run critical security checks for quick scan
        debug!("Running quick security scan");
        let security_findings = self.security_analyzer.quick_scan(&content, path)?;
        findings.extend(security_findings);
        
        // Basic metrics
        metrics.total_lines = content.lines().count();
        metrics.security_score = calculate_security_score(&findings);
        
        Ok(AnalysisResult { findings, metrics })
    }
    
    pub async fn scan_directory(&self, path: &Path) -> Result<Vec<AnalysisResult>> {
        info!("Scanning directory: {}", path.display());
        
        let mut results = Vec::new();
        let mut stack = vec![path.to_path_buf()];
        
        while let Some(current_path) = stack.pop() {
            if current_path.is_file() {
                if self.should_analyze_file(&current_path) {
                    match self.quick_scan(&current_path).await {
                        Ok(result) => results.push(result),
                        Err(e) => {
                            tracing::warn!("Failed to scan {}: {}", current_path.display(), e);
                        }
                    }
                }
            } else if current_path.is_dir() {
                let mut entries = tokio::fs::read_dir(&current_path).await?;
                while let Some(entry) = entries.next_entry().await? {
                    stack.push(entry.path());
                }
            }
        }
        
        Ok(results)
    }

    pub async fn analyze_directory(&mut self, path: &Path) -> Result<Vec<AnalysisResult>> {
        info!("Analyzing directory: {}", path.display());
        
        let mut results = Vec::new();
        let mut entries = tokio::fs::read_dir(path).await?;
        
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_file() && self.should_analyze_file(&path) {
                match self.analyze_file(&path).await {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        tracing::error!("Failed to analyze {}: {}", path.display(), e);
                    }
                }
            } else if path.is_dir() {
                let sub_results = Box::pin(self.analyze_directory(&path)).await?;
                results.extend(sub_results);
            }
        }
        
        Ok(results)
    }
    
    fn should_analyze_file(&self, path: &Path) -> bool {
        match path.extension() {
            Some(ext) => {
                let ext_str = ext.to_string_lossy();
                matches!(ext_str.as_ref(), "go" | "js" | "ts" | "sol" | "rs" | "py")
            }
            None => false,
        }
    }
}

fn calculate_security_score(findings: &[Finding]) -> f64 {
    let critical_count = findings.iter().filter(|f| f.severity == crate::Severity::Critical).count();
    let high_count = findings.iter().filter(|f| f.severity == crate::Severity::High).count();
    let medium_count = findings.iter().filter(|f| f.severity == crate::Severity::Medium).count();
    
    let score = 100.0 - (critical_count as f64 * 20.0) - (high_count as f64 * 10.0) - (medium_count as f64 * 5.0);
    score.max(0.0)
}

fn calculate_performance_score(findings: &[Finding]) -> f64 {
    let perf_findings = findings.iter()
        .filter(|f| f.category.contains("performance"))
        .count();
    
    let score = 100.0 - (perf_findings as f64 * 10.0);
    score.max(0.0)
} 