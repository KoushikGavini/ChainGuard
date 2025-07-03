// ChainGuard - Blockchain Security Analysis Framework
// Copyright (c) 2024

#![warn(clippy::all)]
#![allow(clippy::new_without_default)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::manual_clamp)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::useless_format)]
#![allow(clippy::useless_vec)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::implicit_saturating_sub)]
#![allow(clippy::for_kv_map)]
#![allow(clippy::io_other_error)]
#![allow(clippy::collapsible_if)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(unused_mut)]
#![allow(clippy::uninlined_format_args)]

// Error handling macros
#[macro_export]
macro_rules! try_regex {
    ($pattern:expr) => {{
        match $crate::utils::create_regex($pattern) {
            Ok(regex) => regex,
            Err(e) => {
                tracing::warn!("Failed to compile regex '{}': {}", $pattern, e);
                continue;
            }
        }
    }};
}

#[macro_export]
macro_rules! safe_unwrap {
    ($expr:expr, $default:expr) => {{
        match $expr {
            Some(val) => val,
            None => {
                tracing::debug!("Unwrap failed, using default: {:?}", $default);
                $default
            }
        }
    }};
}

#[macro_export]
macro_rules! try_or_continue {
    ($expr:expr) => {{
        match $expr {
            Ok(val) => val,
            Err(e) => {
                tracing::debug!("Operation failed, skipping: {}", e);
                continue;
            }
        }
    }};
}

pub mod ai_validation;
pub mod analyzer;
pub mod auditor;
pub mod auth;
pub mod benchmark;
pub mod compliance;
pub mod fabric;
// pub mod formal_verification;  // Commented out - requires z3 system dependency
pub mod interactive;
pub mod llm;
pub mod optimizer;
pub mod performance;
pub mod plugins;
pub mod reporter;
pub mod rules;
pub mod solana;
pub mod token_standards;
pub mod utils;
pub mod validator;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ChainGuardError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Analysis error: {0}")]
    Analysis(String),

    #[error("Report generation error: {0}")]
    Report(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("LLM error: {0}")]
    LLM(String),

    #[error("Fabric-specific error: {0}")]
    Fabric(String),

    #[error("Solana-specific error: {0}")]
    Solana(String),

    #[error("Token standard error: {0}")]
    TokenStandard(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Plugin error: {0}")]
    Plugin(String),

    #[error("Formal verification error: {0}")]
    FormalVerification(String),
}

pub type Result<T> = std::result::Result<T, ChainGuardError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ValueEnum)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "Critical"),
            Severity::High => write!(f, "High"),
            Severity::Medium => write!(f, "Medium"),
            Severity::Low => write!(f, "Low"),
            Severity::Info => write!(f, "Info"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub category: String,
    pub title: String,
    pub description: String,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub code_snippet: Option<String>,
    pub remediation: Option<String>,
    pub references: Vec<String>,
    pub ai_consensus: Option<AIConsensus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIConsensus {
    pub models_agreed: Vec<String>,
    pub models_disagreed: Vec<String>,
    pub consensus_level: f32,
    pub explanations: Vec<AIExplanation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIExplanation {
    pub model: String,
    pub explanation: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    pub parallel_analysis: bool,
    pub max_threads: usize,
    pub enable_ai_validation: bool,
    pub enable_performance_analysis: bool,
    pub severity_threshold: Severity,
    pub output_format: OutputFormat,
    pub custom_rules_path: Option<String>,
    pub fabric_specific: bool,
    pub solana_specific: bool,
    pub token_standards: Vec<String>,
    pub ai_models: Vec<String>,
    pub consensus_threshold: f32,
    pub cache_enabled: bool,
    pub cache_dir: Option<String>,
    pub plugin_dir: Option<String>,
    pub formal_verification: bool,
    pub incremental_analysis: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
pub enum OutputFormat {
    Json,
    Html,
    Markdown,
    Pdf,
    Table,
    Xml,
    Csv,
    Sarif,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            parallel_analysis: true,
            max_threads: num_cpus::get(),
            enable_ai_validation: true,
            enable_performance_analysis: true,
            severity_threshold: Severity::Low,
            output_format: OutputFormat::Table,
            custom_rules_path: None,
            fabric_specific: false,
            solana_specific: false,
            token_standards: vec![],
            ai_models: vec!["chatgpt".to_string()],
            consensus_threshold: 0.7,
            cache_enabled: true,
            cache_dir: None,
            plugin_dir: None,
            formal_verification: false,
            incremental_analysis: true,
        }
    }
}

// Module-specific types and traits
pub mod types {
    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AnalysisResult {
        pub file: String,
        pub findings: Vec<Finding>,
        pub metrics: AnalysisMetrics,
        pub ai_validation: Option<AIValidationResult>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AnalysisMetrics {
        pub total_lines: usize,
        pub analyzed_lines: usize,
        pub cyclomatic_complexity: f32,
        pub code_duplication_ratio: f32,
        pub security_score: f32,
        pub performance_score: f32,
        pub compliance_score: f32,
        pub ai_confidence_score: f32,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AIValidationResult {
        pub is_ai_generated: bool,
        pub confidence: f32,
        pub ai_patterns_detected: Vec<String>,
        pub determinism_issues: Vec<String>,
        pub hallucination_risks: Vec<String>,
        pub quality_assessment: String,
    }
}

pub use types::*;

impl From<toml::ser::Error> for ChainGuardError {
    fn from(e: toml::ser::Error) -> Self {
        ChainGuardError::Config(e.to_string())
    }
}

impl From<dialoguer::Error> for ChainGuardError {
    fn from(e: dialoguer::Error) -> Self {
        ChainGuardError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            e.to_string(),
        ))
    }
}

impl From<serde_json::Error> for ChainGuardError {
    fn from(e: serde_json::Error) -> Self {
        ChainGuardError::Report(format!("JSON serialization error: {}", e))
    }
}
