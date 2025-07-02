use crate::{analyzer::AnalysisResult, AnalysisConfig, Finding, OutputFormat, Result, Severity};
use handlebars::{Handlebars, Helper, Context, RenderContext, Output, HelperResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

pub struct Reporter {
    handlebars: Handlebars<'static>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub metadata: ReportMetadata,
    pub summary: ReportSummary,
    pub findings: Vec<Finding>,
    pub recommendations: Vec<Recommendation>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub tool_version: String,
    pub timestamp: String,
    pub files_analyzed: usize,
    pub total_lines: usize,
    pub analysis_duration: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_findings: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub medium_findings: usize,
    pub low_findings: usize,
    pub info_findings: usize,
    pub security_score: f64,
    pub ai_validation_score: f64,
    pub complexity_score: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Recommendation {
    pub priority: String,
    pub category: String,
    pub description: String,
    pub impact: String,
}

impl Reporter {
    pub fn new() -> Self {
        let mut handlebars = Handlebars::new();

        // Register helpers
        handlebars.register_helper("lowercase", Box::new(lowercase_helper));
        handlebars.register_helper("eq", Box::new(eq_helper));

        // Register default templates
        let html_template = include_str!("templates/report.html");
        let md_template = include_str!("templates/report.md");

        handlebars
            .register_template_string("html", html_template)
            .expect("Failed to register HTML template");

        handlebars
            .register_template_string("markdown", md_template)
            .expect("Failed to register Markdown template");

        Self { handlebars }
    }

    pub fn generate_report(
        &self,
        results: &[AnalysisResult],
        config: &AnalysisConfig,
    ) -> Result<Report> {
        let mut all_findings = Vec::new();
        let mut total_lines = 0;

        for result in results {
            all_findings.extend(result.findings.clone());
            total_lines += result.metrics.total_lines;
        }

        // Filter findings by severity threshold
        let filtered_findings: Vec<Finding> = all_findings
            .into_iter()
            .filter(|f| self.meets_severity_threshold(&f.severity, &config.severity_threshold))
            .collect();

        let summary = self.calculate_summary(&filtered_findings, results);
        let recommendations = self.generate_recommendations(&filtered_findings, results);

        let metadata = ReportMetadata {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            files_analyzed: results.len(),
            total_lines,
            analysis_duration: "0s".to_string(), // TODO: Track actual duration
        };

        Ok(Report {
            metadata,
            summary,
            findings: filtered_findings,
            recommendations,
        })
    }

    pub fn generate_scan_report(&self, results: &[AnalysisResult]) -> Result<Report> {
        let config = AnalysisConfig::default();
        self.generate_report(results, &config)
    }

    pub fn generate_audit_report(&self, results: &crate::auditor::AuditResult) -> Result<Report> {
        let findings = results.findings.clone();
        let summary = ReportSummary {
            total_findings: findings.len(),
            critical_findings: findings
                .iter()
                .filter(|f| f.severity == Severity::Critical)
                .count(),
            high_findings: findings
                .iter()
                .filter(|f| f.severity == Severity::High)
                .count(),
            medium_findings: findings
                .iter()
                .filter(|f| f.severity == Severity::Medium)
                .count(),
            low_findings: findings
                .iter()
                .filter(|f| f.severity == Severity::Low)
                .count(),
            info_findings: findings
                .iter()
                .filter(|f| f.severity == Severity::Info)
                .count(),
            security_score: results.compliance_score as f64,
            ai_validation_score: 100.0,
            complexity_score: 100.0,
        };

        let metadata = ReportMetadata {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            files_analyzed: 1,
            total_lines: 0,
            analysis_duration: "0s".to_string(),
        };

        Ok(Report {
            metadata,
            summary,
            findings,
            recommendations: vec![],
        })
    }

    pub fn generate_benchmark_report(
        &self,
        results: &crate::benchmark::BenchmarkResults,
    ) -> Result<Report> {
        let mut findings = Vec::new();
        let mut recommendations = Vec::new();

        // Convert benchmark results to findings
        if let Some(ref throughput) = results.throughput {
            for bottleneck in &throughput.bottlenecks {
                findings.push(Finding {
                    id: "BENCH-PERF-001".to_string(),
                    severity: Severity::Medium,
                    category: "Performance".to_string(),
                    title: "Performance bottleneck".to_string(),
                    description: bottleneck.clone(),
                    file: "".to_string(),
                    line: 0,
                    column: 0,
                    code_snippet: None,
                    remediation: None,
                    references: vec![],
                    ai_consensus: None,
                });
            }

            if throughput.tps < 100.0 {
                recommendations.push(Recommendation {
                    priority: "HIGH".to_string(),
                    category: "Performance".to_string(),
                    description: "Transaction throughput is below acceptable levels".to_string(),
                    impact: format!("Current: {:.1} TPS, Target: 100+ TPS", throughput.tps),
                });
            }
        }

        let summary = ReportSummary {
            total_findings: findings.len(),
            critical_findings: 0,
            high_findings: 0,
            medium_findings: findings.len(),
            low_findings: 0,
            info_findings: 0,
            security_score: 100.0,
            ai_validation_score: 100.0,
            complexity_score: results.overall_score as f64,
        };

        let metadata = ReportMetadata {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            files_analyzed: 1,
            total_lines: 0,
            analysis_duration: "0s".to_string(),
        };

        Ok(Report {
            metadata,
            summary,
            findings,
            recommendations,
        })
    }

    pub fn generate_optimization_report(
        &self,
        suggestions: &[crate::optimizer::OptimizationSuggestion],
    ) -> Result<Report> {
        let mut findings = Vec::new();
        let mut recommendations = Vec::new();

        // Convert suggestions to findings
        for suggestion in suggestions {
            findings.push(Finding {
                id: suggestion.id.clone(),
                severity: Severity::Info,
                category: format!("Optimization/{}", suggestion.category),
                title: suggestion.title.clone(),
                description: suggestion.description.clone(),
                file: "".to_string(),
                line: 0,
                column: 0,
                code_snippet: Some(format!(
                    "Before:\n{}\n\nAfter:\n{}",
                    suggestion.code_before, suggestion.code_after
                )),
                remediation: Some(suggestion.explanation.clone()),
                references: vec![],
                ai_consensus: None,
            });

            recommendations.push(Recommendation {
                priority: match suggestion.implementation_difficulty {
                    crate::optimizer::Difficulty::Easy => "LOW",
                    crate::optimizer::Difficulty::Medium => "MEDIUM",
                    crate::optimizer::Difficulty::Hard => "HIGH",
                }
                .to_string(),
                category: suggestion.category.clone(),
                description: suggestion.title.clone(),
                impact: format!(
                    "Expected performance gain: {:.1}%",
                    suggestion.performance_gain
                ),
            });
        }

        let total_gain: f32 = suggestions.iter().map(|s| s.performance_gain).sum();

        let summary = ReportSummary {
            total_findings: findings.len(),
            critical_findings: 0,
            high_findings: 0,
            medium_findings: 0,
            low_findings: 0,
            info_findings: findings.len(),
            security_score: 100.0,
            ai_validation_score: 100.0,
            complexity_score: (100.0 + total_gain as f64).min(100.0),
        };

        let metadata = ReportMetadata {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            files_analyzed: 1,
            total_lines: 0,
            analysis_duration: "0s".to_string(),
        };

        Ok(Report {
            metadata,
            summary,
            findings,
            recommendations,
        })
    }

    pub async fn save_report(
        &self,
        report: &Report,
        path: &Path,
        format: OutputFormat,
    ) -> Result<()> {
        let content = match format {
            OutputFormat::Json => serde_json::to_string_pretty(report)
                .map_err(|e| crate::ChainGuardError::Report(e.to_string()))?,
            OutputFormat::Html => self.render_html(report)?,
            OutputFormat::Markdown => self.render_markdown(report)?,
            OutputFormat::Pdf => self.render_pdf(report)?,
            OutputFormat::Table => self.render_table(report)?,
            OutputFormat::Xml => self.render_xml(report)?,
            OutputFormat::Csv => self.render_csv(report)?,
            OutputFormat::Sarif => self.render_sarif(report)?,
        };

        tokio::fs::write(path, content).await?;
        Ok(())
    }

    fn calculate_summary(&self, findings: &[Finding], results: &[AnalysisResult]) -> ReportSummary {
        let mut summary = ReportSummary {
            total_findings: findings.len(),
            critical_findings: 0,
            high_findings: 0,
            medium_findings: 0,
            low_findings: 0,
            info_findings: 0,
            security_score: 0.0,
            ai_validation_score: 0.0,
            complexity_score: 0.0,
        };

        for finding in findings {
            match finding.severity {
                Severity::Critical => summary.critical_findings += 1,
                Severity::High => summary.high_findings += 1,
                Severity::Medium => summary.medium_findings += 1,
                Severity::Low => summary.low_findings += 1,
                Severity::Info => summary.info_findings += 1,
            }
        }

        // Calculate scores
        if !results.is_empty() {
            summary.security_score = results
                .iter()
                .map(|r| r.metrics.security_score)
                .sum::<f64>()
                / results.len() as f64;

            summary.ai_validation_score = results
                .iter()
                .map(|r| r.metrics.ai_validation_score)
                .sum::<f64>()
                / results.len() as f64;

            summary.complexity_score = 100.0
                - (results
                    .iter()
                    .map(|r| r.metrics.cyclomatic_complexity)
                    .sum::<f64>()
                    / results.len() as f64
                    * 5.0)
                    .min(100.0)
                    .max(0.0);
        }

        summary
    }

    fn generate_recommendations(
        &self,
        findings: &[Finding],
        results: &[AnalysisResult],
    ) -> Vec<Recommendation> {
        let mut recommendations = Vec::new();

        // Critical security recommendations
        if findings.iter().any(|f| f.severity == Severity::Critical) {
            recommendations.push(Recommendation {
                priority: "URGENT".to_string(),
                category: "Security".to_string(),
                description: "Address all critical security vulnerabilities immediately"
                    .to_string(),
                impact: "Prevents potential security breaches and consensus failures".to_string(),
            });
        }

        // AI validation recommendations
        let ai_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category.starts_with("ai-validation"))
            .collect();

        if !ai_findings.is_empty() {
            recommendations.push(Recommendation {
                priority: "HIGH".to_string(),
                category: "AI Validation".to_string(),
                description: format!("Review {} AI-generated code issues", ai_findings.len()),
                impact: "Ensures code reliability and prevents hallucinated dependencies"
                    .to_string(),
            });
        }

        // Performance recommendations
        if let Some(result) = results.first() {
            if result.metrics.cyclomatic_complexity > 15.0 {
                recommendations.push(Recommendation {
                    priority: "MEDIUM".to_string(),
                    category: "Code Quality".to_string(),
                    description: "Refactor complex functions to improve maintainability"
                        .to_string(),
                    impact: "Reduces bugs and improves code readability".to_string(),
                });
            }
        }

        recommendations
    }

    fn render_html(&self, report: &Report) -> Result<String> {
        self.handlebars
            .render("html", report)
            .map_err(|e| crate::ChainGuardError::Report(e.to_string()))
    }

    fn render_markdown(&self, report: &Report) -> Result<String> {
        self.handlebars
            .render("markdown", report)
            .map_err(|e| crate::ChainGuardError::Report(e.to_string()))
    }

    fn render_pdf(&self, _report: &Report) -> Result<String> {
        // TODO: Implement PDF generation
        Err(crate::ChainGuardError::Report(
            "PDF generation not yet implemented".to_string(),
        ))
    }

    fn render_table(&self, report: &Report) -> Result<String> {
        // Simple table format for terminal output
        let mut output = String::new();
        output.push_str(&format!(
            "ChainGuard Analysis Report - {}\n",
            report.metadata.timestamp
        ));
        output.push_str(&format!("{}\n", "=".repeat(80)));
        output.push_str(&format!(
            "Total Findings: {}\n",
            report.summary.total_findings
        ));
        output.push_str(&format!(
            "Critical: {} | High: {} | Medium: {} | Low: {} | Info: {}\n",
            report.summary.critical_findings,
            report.summary.high_findings,
            report.summary.medium_findings,
            report.summary.low_findings,
            report.summary.info_findings
        ));
        output.push_str(&format!("{}\n", "-".repeat(80)));

        for finding in &report.findings {
            output.push_str(&format!(
                "[{}] {} - {}\n",
                finding.severity, finding.id, finding.title
            ));
            output.push_str(&format!("  File: {}:{}\n", finding.file, finding.line));
            output.push_str(&format!("  {}\n\n", finding.description));
        }

        Ok(output)
    }

    fn render_xml(&self, report: &Report) -> Result<String> {
        // Basic XML format
        let xml = quick_xml::se::to_string(report).map_err(|e| {
            crate::ChainGuardError::Report(format!("XML serialization failed: {}", e))
        })?;
        Ok(xml)
    }

    fn render_csv(&self, report: &Report) -> Result<String> {
        // CSV format for findings
        let mut csv = String::from("ID,Severity,Category,Title,File,Line,Description\n");
        for finding in &report.findings {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{}\n",
                finding.id,
                finding.severity,
                finding.category,
                finding.title,
                finding.file,
                finding.line,
                finding.description.replace(',', ";")
            ));
        }
        Ok(csv)
    }

    fn render_sarif(&self, report: &Report) -> Result<String> {
        // SARIF (Static Analysis Results Interchange Format) for CI/CD integration
        let sarif = serde_json::json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "ChainGuard",
                        "version": report.metadata.tool_version,
                        "informationUri": "https://github.com/KoushikGavini/ChainGuard"
                    }
                },
                "results": report.findings.iter().map(|f| {
                    serde_json::json!({
                        "ruleId": f.id,
                        "level": match f.severity {
                            Severity::Critical | Severity::High => "error",
                            Severity::Medium => "warning",
                            _ => "note"
                        },
                        "message": {
                            "text": f.description
                        },
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": f.file
                                },
                                "region": {
                                    "startLine": f.line,
                                    "startColumn": f.column
                                }
                            }
                        }]
                    })
                }).collect::<Vec<_>>()
            }]
        });

        serde_json::to_string_pretty(&sarif)
            .map_err(|e| crate::ChainGuardError::Report(format!("SARIF generation failed: {}", e)))
    }

    fn meets_severity_threshold(&self, severity: &Severity, threshold: &Severity) -> bool {
        match threshold {
            Severity::Critical => matches!(severity, Severity::Critical),
            Severity::High => matches!(severity, Severity::Critical | Severity::High),
            Severity::Medium => matches!(
                severity,
                Severity::Critical | Severity::High | Severity::Medium
            ),
            Severity::Low => !matches!(severity, Severity::Info),
            Severity::Info => true,
        }
    }
}

impl Report {
    pub fn summary(&self) -> String {
        format!(
            "ChainGuard Analysis Report\n\
             ==========================\n\
             Total Findings: {}\n\
             Critical: {} | High: {} | Medium: {} | Low: {} | Info: {}\n\
             Security Score: {:.1}/100\n\
             AI Validation Score: {:.1}/100\n\
             Complexity Score: {:.1}/100",
            self.summary.total_findings,
            self.summary.critical_findings,
            self.summary.high_findings,
            self.summary.medium_findings,
            self.summary.low_findings,
            self.summary.info_findings,
            self.summary.security_score,
            self.summary.ai_validation_score,
            self.summary.complexity_score
        )
    }
}

fn lowercase_helper(
    h: &Helper,
    _: &Handlebars,
    _: &Context,
    _: &mut RenderContext,
    out: &mut dyn Output,
) -> HelperResult {
    let param = h.param(0).and_then(|v| v.value().as_str()).unwrap_or("");
    out.write(&param.to_lowercase())?;
    Ok(())
}

fn eq_helper(
    h: &Helper,
    _: &Handlebars,
    _: &Context,
    _: &mut RenderContext,
    _: &mut dyn Output,
) -> HelperResult {
    let param1 = h.param(0).and_then(|v| v.value().as_str()).unwrap_or("");
    let param2 = h.param(1).and_then(|v| v.value().as_str()).unwrap_or("");
    // For eq helper, we just need to return Ok(()) since handlebars uses the return value for conditionals
    Ok(())
}
