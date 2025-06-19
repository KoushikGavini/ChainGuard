use crate::{Result, ChainGuardError, Finding, Severity, AIConsensus, AIExplanation};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::sync::Arc;

// pub mod chatgpt;
// pub mod claude;
// pub mod gemini; // Commented out - implementations not included in this version

#[async_trait]
pub trait LLMProvider: Send + Sync {
    async fn analyze_code(&self, code: &str, context: &AnalysisContext) -> Result<LLMAnalysisResult>;
    async fn suggest_fix(&self, finding: &Finding, code: &str) -> Result<String>;
    async fn validate_ai_generated(&self, code: &str) -> Result<AIGeneratedValidation>;
    async fn test_connection(&self) -> Result<()>;
    fn name(&self) -> &str;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisContext {
    pub file_path: String,
    pub language: String,
    pub platform: String,
    pub focus_areas: Vec<String>,
    pub custom_rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMAnalysisResult {
    pub findings: Vec<Finding>,
    pub suggestions: Vec<CodeSuggestion>,
    pub confidence: f32,
    pub model_name: String,
    pub reasoning: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSuggestion {
    pub title: String,
    pub description: String,
    pub original_code: String,
    pub suggested_code: String,
    pub performance_gain: f32,
    pub security_improvement: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIGeneratedValidation {
    pub is_ai_generated: bool,
    pub confidence: f32,
    pub patterns_detected: Vec<String>,
    pub hallucination_risks: Vec<HallucinationRisk>,
    pub determinism_issues: Vec<DeterminismIssue>,
    pub quality_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HallucinationRisk {
    pub risk_type: String,
    pub description: String,
    pub severity: Severity,
    pub location: CodeLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeterminismIssue {
    pub issue_type: String,
    pub description: String,
    pub impact: String,
    pub location: CodeLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeLocation {
    pub line: usize,
    pub column: usize,
    pub snippet: String,
}

pub struct LLMManager {
    providers: Arc<RwLock<HashMap<String, Box<dyn LLMProvider>>>>,
    client: Client,
    config: LLMConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMConfig {
    pub timeout_seconds: u64,
    pub max_retries: usize,
    pub consensus_threshold: f32,
    pub cache_responses: bool,
    pub prompt_injection_protection: bool,
}

impl Default for LLMConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 30,
            max_retries: 3,
            consensus_threshold: 0.7,
            cache_responses: true,
            prompt_injection_protection: true,
        }
    }
}

impl LLMManager {
    pub async fn new() -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| ChainGuardError::Network(e))?;
        
        Ok(Self {
            providers: Arc::new(RwLock::new(HashMap::new())),
            client,
            config: LLMConfig::default(),
        })
    }
    
    pub async fn with_config(config: LLMConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_seconds))
            .build()
            .map_err(|e| ChainGuardError::Network(e))?;
        
        Ok(Self {
            providers: Arc::new(RwLock::new(HashMap::new())),
            client,
            config,
        })
    }
    
    pub async fn add_provider(&mut self, name: String, provider: Box<dyn LLMProvider>) -> Result<()> {
        // Test connection first
        provider.test_connection().await?;
        
        let mut providers = self.providers.write().await;
        providers.insert(name, provider);
        Ok(())
    }
    
    pub async fn analyze_with_consensus(
        &self,
        code: &str,
        context: &AnalysisContext,
    ) -> Result<ConsensusAnalysisResult> {
        let providers = self.providers.read().await;
        
        if providers.is_empty() {
            return Err(ChainGuardError::LLM("No LLM providers configured".to_string()));
        }
        
        let mut results = Vec::new();
        let mut tasks = Vec::new();
        
        // Collect all providers
        let provider_list: Vec<_> = providers.iter().collect();
        
        // Create analysis tasks for each provider
        for (name, provider) in provider_list {
            let code = code.to_string();
            let context = context.clone();
            let provider = provider.clone();
            
            let task = tokio::spawn(async move {
                (name.clone(), provider.analyze_code(&code, &context).await)
            });
            
            tasks.push(task);
        }
        
        // Wait for all analyses to complete
        for task in tasks {
            match task.await {
                Ok((name, result)) => {
                    match result {
                        Ok(analysis) => results.push((name, analysis)),
                        Err(e) => tracing::warn!("Provider {} failed: {}", name, e),
                    }
                }
                Err(e) => tracing::warn!("Task failed: {}", e),
            }
        }
        
        if results.is_empty() {
            return Err(ChainGuardError::LLM("All providers failed".to_string()));
        }
        
        // Build consensus
        self.build_consensus(results).await
    }
    
    async fn build_consensus(
        &self,
        results: Vec<(String, LLMAnalysisResult)>,
    ) -> Result<ConsensusAnalysisResult> {
        let mut consensus_findings: HashMap<String, ConsensusFindings> = HashMap::new();
        
        // Aggregate findings from all providers
        for (provider_name, result) in &results {
            for finding in &result.findings {
                let key = format!("{}:{}:{}", finding.category, finding.file, finding.line);
                
                let consensus = consensus_findings.entry(key).or_insert_with(|| {
                    ConsensusFindings {
                        finding: finding.clone(),
                        providers_agreed: vec![],
                        providers_disagreed: vec![],
                        explanations: vec![],
                    }
                });
                
                consensus.providers_agreed.push(provider_name.clone());
                consensus.explanations.push(AIExplanation {
                    model: provider_name.clone(),
                    explanation: result.reasoning.clone(),
                    confidence: result.confidence,
                });
            }
        }
        
        // Calculate consensus level and filter findings
        let mut final_findings = Vec::new();
        let total_providers = results.len() as f32;
        
        for (_, mut consensus) in consensus_findings {
            let consensus_level = consensus.providers_agreed.len() as f32 / total_providers;
            
            if consensus_level >= self.config.consensus_threshold {
                consensus.finding.ai_consensus = Some(AIConsensus {
                    models_agreed: consensus.providers_agreed.clone(),
                    models_disagreed: consensus.providers_disagreed.clone(),
                    consensus_level,
                    explanations: consensus.explanations.clone(),
                });
                
                final_findings.push(consensus.finding);
            }
        }
        
        // Aggregate suggestions
        let mut all_suggestions = Vec::new();
        for (_, result) in results {
            all_suggestions.extend(result.suggestions);
        }
        
        Ok(ConsensusAnalysisResult {
            findings: final_findings,
            suggestions: all_suggestions,
            providers_used: results.len(),
            consensus_achieved: true,
        })
    }
    
    pub async fn validate_ai_generated_with_consensus(
        &self,
        code: &str,
    ) -> Result<AIGeneratedValidation> {
        let providers = self.providers.read().await;
        
        if providers.is_empty() {
            return Err(ChainGuardError::LLM("No LLM providers configured".to_string()));
        }
        
        let mut validations = Vec::new();
        let mut tasks = Vec::new();
        
        for (name, provider) in providers.iter() {
            let code = code.to_string();
            let provider = provider.clone();
            
            let task = tokio::spawn(async move {
                provider.validate_ai_generated(&code).await
            });
            
            tasks.push(task);
        }
        
        // Collect validation results
        for task in tasks {
            if let Ok(Ok(validation)) = task.await {
                validations.push(validation);
            }
        }
        
        if validations.is_empty() {
            return Err(ChainGuardError::LLM("All validation attempts failed".to_string()));
        }
        
        // Aggregate validation results
        self.aggregate_validations(validations)
    }
    
    fn aggregate_validations(&self, validations: Vec<AIGeneratedValidation>) -> Result<AIGeneratedValidation> {
        let count = validations.len() as f32;
        
        let avg_confidence = validations.iter()
            .map(|v| v.confidence)
            .sum::<f32>() / count;
        
        let is_ai_generated = validations.iter()
            .filter(|v| v.is_ai_generated)
            .count() as f32 / count >= 0.5;
        
        let mut all_patterns = Vec::new();
        let mut all_hallucination_risks = Vec::new();
        let mut all_determinism_issues = Vec::new();
        
        for validation in validations {
            all_patterns.extend(validation.patterns_detected);
            all_hallucination_risks.extend(validation.hallucination_risks);
            all_determinism_issues.extend(validation.determinism_issues);
        }
        
        // Deduplicate patterns
        all_patterns.sort();
        all_patterns.dedup();
        
        let avg_quality = validations.iter()
            .map(|v| v.quality_score)
            .sum::<f32>() / count;
        
        Ok(AIGeneratedValidation {
            is_ai_generated,
            confidence: avg_confidence,
            patterns_detected: all_patterns,
            hallucination_risks: all_hallucination_risks,
            determinism_issues: all_determinism_issues,
            quality_score: avg_quality,
        })
    }
}

#[derive(Debug, Clone)]
struct ConsensusFindings {
    finding: Finding,
    providers_agreed: Vec<String>,
    providers_disagreed: Vec<String>,
    explanations: Vec<AIExplanation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusAnalysisResult {
    pub findings: Vec<Finding>,
    pub suggestions: Vec<CodeSuggestion>,
    pub providers_used: usize,
    pub consensus_achieved: bool,
} 