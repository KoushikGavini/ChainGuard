#![allow(unused_variables)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::uninlined_format_args)]

use chainguard::{
    analyzer::{AnalysisResult, Analyzer},
    fabric::FabricAnalyzer,
    llm::LLMManager,
    reporter::{Report, Reporter},
    solana::SolanaAnalyzer,
    token_standards::TokenStandardsValidator,
    validator::Validator,
    AnalysisConfig, ChainGuardError, OutputFormat, Result, Severity,
};
use clap::{Parser, Subcommand, ValueEnum};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use tracing::Level;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

#[derive(Parser)]
#[command(name = "chainguard")]
#[command(about = "Advanced security analysis for blockchain platforms with Hyperledger Fabric specialization", long_about = None)]
#[command(version)]
#[command(author)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Set the verbosity level
    #[arg(short, long, global = true, default_value = "info")]
    verbosity: String,

    /// Output format for results
    #[arg(short = 'o', long, global = true, value_enum, default_value = "table")]
    output: OutputFormat,

    /// Enable parallel analysis
    #[arg(long, global = true)]
    parallel: bool,

    /// Number of threads for parallel analysis
    #[arg(long, global = true)]
    threads: Option<usize>,

    /// Enable colored output
    #[arg(long, global = true, default_value = "true")]
    color: bool,

    /// Quiet mode - suppress non-essential output
    #[arg(short, long, global = true)]
    quiet: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Comprehensive security and quality analysis
    Analyze {
        /// Path to chaincode file or directory
        path: PathBuf,

        /// Enable Hyperledger Fabric-specific analysis
        #[arg(long)]
        fabric: bool,

        /// Enable Solana-specific analysis
        #[arg(long)]
        solana: bool,

        /// Enable AI-generated code validation
        #[arg(long)]
        ai_validate: bool,

        /// Specify ERC standards to validate (comma-separated: erc20,erc721,erc1155,erc777)
        #[arg(long, value_delimiter = ',')]
        standards: Vec<String>,

        /// Enable AI plugin integrations (comma-separated: chatgpt,claude,gemini)
        #[arg(long, value_delimiter = ',')]
        ai_plugins: Vec<String>,

        /// Minimum severity level to report
        #[arg(short, long, value_enum, default_value = "low")]
        severity: Severity,

        /// Return non-zero exit code on findings
        #[arg(long)]
        exit_code: bool,

        /// Compare against previous scan results
        #[arg(long)]
        baseline: Option<PathBuf>,

        /// Specify custom configuration file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Set required AI consensus level
        #[arg(long, value_enum)]
        consensus_level: Option<ConsensusLevel>,

        /// Specify primary AI model for analysis
        #[arg(long, value_enum)]
        ai_model: Option<AIModel>,

        /// Output file path
        #[arg(long)]
        output_file: Option<PathBuf>,

        /// Include file patterns (glob)
        #[arg(long)]
        include: Vec<String>,

        /// Exclude file patterns (glob)
        #[arg(long)]
        exclude: Vec<String>,
    },

    /// Quick vulnerability scanning
    Scan {
        /// Path to chaincode file or directory
        path: PathBuf,

        /// Enable Hyperledger Fabric-specific scanning
        #[arg(long)]
        fabric: bool,

        /// Enable Solana-specific scanning
        #[arg(long)]
        solana: bool,

        /// Minimum severity level to report
        #[arg(short, long, value_enum, default_value = "medium")]
        severity: Severity,

        /// Return non-zero exit code on findings
        #[arg(long)]
        exit_code: bool,

        /// Output file path
        #[arg(long)]
        output_file: Option<PathBuf>,
    },

    /// Compliance and standards checking
    Audit {
        /// Path to chaincode file or directory
        path: PathBuf,

        /// Enable Hyperledger Fabric compliance checking
        #[arg(long)]
        fabric: bool,

        /// Enable Solana compliance checking
        #[arg(long)]
        solana: bool,

        /// Specify ERC standards to audit (comma-separated)
        #[arg(long, value_delimiter = ',')]
        standards: Vec<String>,

        /// Audit against specific compliance framework
        #[arg(long)]
        framework: Option<String>,

        /// Output file path
        #[arg(long)]
        output_file: Option<PathBuf>,
    },

    /// AI-generated code validation
    Validate {
        /// Path to chaincode file or directory
        path: PathBuf,

        /// Enable multi-AI consensus validation
        #[arg(long)]
        consensus: bool,

        /// Set required AI consensus level
        #[arg(long, value_enum)]
        consensus_level: Option<ConsensusLevel>,

        /// Enable real-time validation feedback
        #[arg(long)]
        realtime: bool,

        /// Check for hallucinated dependencies
        #[arg(long, default_value = "true")]
        check_deps: bool,

        /// Validate determinism requirements
        #[arg(long, default_value = "true")]
        determinism: bool,

        /// Output file path
        #[arg(long)]
        output_file: Option<PathBuf>,
    },

    /// Performance analysis and benchmarking
    Benchmark {
        /// Path to chaincode file or directory
        path: PathBuf,

        /// Enable Fabric-specific performance analysis
        #[arg(long)]
        fabric: bool,

        /// Enable Solana-specific performance analysis
        #[arg(long)]
        solana: bool,

        /// Analyze transaction throughput
        #[arg(long)]
        throughput: bool,

        /// Analyze state storage efficiency
        #[arg(long)]
        storage: bool,

        /// Analyze consensus impact
        #[arg(long)]
        consensus: bool,

        /// Output file path
        #[arg(long)]
        output_file: Option<PathBuf>,
    },

    /// Generate detailed reports from previous scans
    Report {
        /// Path to analysis results or directory
        input: PathBuf,

        /// Report format
        #[arg(short = 'f', long, value_enum, default_value = "html")]
        format: ReportFormat,

        /// Report template to use
        #[arg(short, long, default_value = "default")]
        template: String,

        /// Include remediation guidance
        #[arg(long, default_value = "true")]
        remediation: bool,

        /// Include code examples
        #[arg(long, default_value = "true")]
        examples: bool,

        /// Output file path
        #[arg(long)]
        output_file: PathBuf,
    },

    /// AI-powered performance optimization suggestions
    Optimize {
        /// Path to chaincode file or directory
        path: PathBuf,

        /// Target platform (fabric, solana, etc.)
        #[arg(long, default_value = "fabric")]
        platform: String,

        /// Enable AI-powered suggestions
        #[arg(long, default_value = "true")]
        ai_suggestions: bool,

        /// Optimization focus areas (comma-separated)
        #[arg(long, value_delimiter = ',')]
        focus: Vec<String>,

        /// Apply optimizations automatically
        #[arg(long)]
        auto_apply: bool,

        /// Output file path
        #[arg(long)]
        output_file: Option<PathBuf>,
    },

    /// Initialize configuration
    Init {
        /// Configuration file path
        #[arg(short, long, default_value = "chainguard.toml")]
        config: PathBuf,

        /// Initialize for specific platform
        #[arg(long)]
        platform: Option<String>,

        /// Include example rules
        #[arg(long)]
        examples: bool,

        /// Force overwrite existing configuration
        #[arg(short, long)]
        force: bool,
    },

    /// Manage AI integrations and API keys
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },

    /// Show analysis history
    History {
        /// Number of recent analyses to show
        #[arg(short, long, default_value = "10")]
        limit: usize,

        /// Filter by file path pattern
        #[arg(short, long)]
        filter: Option<String>,

        /// Show detailed results
        #[arg(long)]
        detailed: bool,

        /// Export history to file
        #[arg(long)]
        export: Option<PathBuf>,
    },

    /// Manage custom rules
    Rules {
        #[command(subcommand)]
        command: RulesCommands,
    },

    /// Interactive mode with live validation
    Interactive {
        /// Initial path to analyze
        path: Option<PathBuf>,

        /// Enable AI assistance
        #[arg(long, default_value = "true")]
        ai_assist: bool,
    },
}

#[derive(Subcommand)]
enum AuthCommands {
    /// Configure API key for a service
    Set {
        /// Service name (chatgpt, claude, gemini)
        service: String,

        /// API key (will prompt if not provided)
        #[arg(long)]
        key: Option<String>,
    },

    /// Remove API key for a service
    Remove {
        /// Service name
        service: String,
    },

    /// List configured services
    List,

    /// Test API connections
    Test {
        /// Service to test (or 'all')
        service: Option<String>,
    },
}

#[derive(Subcommand)]
enum RulesCommands {
    /// List available rules
    List {
        /// Filter by category
        #[arg(long)]
        category: Option<String>,

        /// Show disabled rules
        #[arg(long)]
        all: bool,
    },

    /// Enable a rule
    Enable {
        /// Rule ID or pattern
        rule: String,
    },

    /// Disable a rule
    Disable {
        /// Rule ID or pattern
        rule: String,
    },

    /// Import custom rules
    Import {
        /// Path to rules file
        path: PathBuf,

        /// Validate rules before importing
        #[arg(long, default_value = "true")]
        validate: bool,
    },

    /// Export current rules configuration
    Export {
        /// Output path
        path: PathBuf,

        /// Include custom rules only
        #[arg(long)]
        custom_only: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ConsensusLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum AIModel {
    ChatGPT,
    Claude,
    Gemini,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ReportFormat {
    Html,
    Pdf,
    Markdown,
    Json,
    Xml,
    Csv,
    Sarif,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let level = match cli.verbosity.as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let filter = EnvFilter::from_default_env()
        .add_directive(level.into())
        .add_directive("chainguard=debug".parse().unwrap());

    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(cli.color)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    // Set color mode
    if !cli.color {
        console::set_colors_enabled(false);
    }

    match cli.command {
        Commands::Analyze {
            path,
            fabric,
            solana,
            ai_validate,
            standards,
            ai_plugins,
            severity,
            exit_code,
            baseline,
            config,
            consensus_level,
            ai_model,
            output_file,
            include,
            exclude,
        } => {
            let exit_code_val = analyze_command(
                path,
                fabric,
                solana,
                ai_validate,
                standards,
                ai_plugins,
                severity,
                exit_code,
                baseline,
                config,
                consensus_level,
                ai_model,
                output_file,
                include,
                exclude,
                cli.output,
                cli.parallel,
                cli.threads,
                cli.quiet,
            )
            .await?;

            if exit_code && exit_code_val > 0 {
                std::process::exit(exit_code_val);
            }
        }

        Commands::Scan {
            path,
            fabric,
            solana,
            severity,
            exit_code,
            output_file,
        } => {
            let exit_code_val = scan_command(
                path,
                fabric,
                solana,
                severity,
                output_file,
                cli.output,
                cli.quiet,
            )
            .await?;

            if exit_code && exit_code_val > 0 {
                std::process::exit(exit_code_val);
            }
        }

        Commands::Audit {
            path,
            fabric,
            solana,
            standards,
            framework,
            output_file,
        } => {
            audit_command(
                path,
                fabric,
                solana,
                standards,
                framework,
                output_file,
                cli.output,
                cli.quiet,
            )
            .await?;
        }

        Commands::Validate {
            path,
            consensus,
            consensus_level,
            realtime,
            check_deps,
            determinism,
            output_file,
        } => {
            validate_command(
                path,
                consensus,
                consensus_level,
                realtime,
                check_deps,
                determinism,
                output_file,
                cli.output,
                cli.quiet,
            )
            .await?;
        }

        Commands::Benchmark {
            path,
            fabric,
            solana,
            throughput,
            storage,
            consensus,
            output_file,
        } => {
            benchmark_command(
                path,
                fabric,
                solana,
                throughput,
                storage,
                consensus,
                output_file,
                cli.output,
                cli.quiet,
            )
            .await?;
        }

        Commands::Report {
            input,
            format,
            template,
            remediation,
            examples,
            output_file,
        } => {
            report_command(
                input,
                format,
                template,
                remediation,
                examples,
                output_file,
                cli.quiet,
            )
            .await?;
        }

        Commands::Optimize {
            path,
            platform,
            ai_suggestions,
            focus,
            auto_apply,
            output_file,
        } => {
            optimize_command(
                path,
                platform,
                ai_suggestions,
                focus,
                auto_apply,
                output_file,
                cli.output,
                cli.quiet,
            )
            .await?;
        }

        Commands::Init {
            config,
            platform,
            examples,
            force,
        } => {
            init_command(config, platform, examples, force).await?;
        }

        Commands::Auth { command } => {
            auth_command(command).await?;
        }

        Commands::History {
            limit,
            filter,
            detailed,
            export,
        } => {
            history_command(limit, filter, detailed, export, cli.output).await?;
        }

        Commands::Rules { command } => {
            rules_command(command).await?;
        }

        Commands::Interactive { path, ai_assist } => {
            interactive_command(path, ai_assist).await?;
        }
    }

    Ok(())
}

async fn analyze_command(
    path: PathBuf,
    fabric: bool,
    solana: bool,
    ai_validate: bool,
    standards: Vec<String>,
    ai_plugins: Vec<String>,
    severity: Severity,
    exit_code: bool,
    baseline: Option<PathBuf>,
    config_path: Option<PathBuf>,
    consensus_level: Option<ConsensusLevel>,
    ai_model: Option<AIModel>,
    output_file: Option<PathBuf>,
    include: Vec<String>,
    exclude: Vec<String>,
    format: OutputFormat,
    parallel: bool,
    threads: Option<usize>,
    quiet: bool,
) -> Result<i32> {
    println!("{}", style("🔍 Chainguard Analysis").bold().cyan());
    println!("{}", style("━".repeat(50)).dim());

    // Load or create configuration
    let mut config = if let Some(path) = config_path {
        load_config(&path).await?
    } else {
        AnalysisConfig::default()
    };

    config.severity_threshold = severity;
    config.enable_ai_validation = ai_validate;
    config.enable_performance_analysis = true;
    config.output_format = format;
    config.parallel_analysis = parallel;
    config.fabric_specific = fabric;
    config.solana_specific = solana;
    if let Some(t) = threads {
        config.max_threads = t;
    }

    // Initialize components
    let progress = ProgressBar::new_spinner();
    progress.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );

    progress.set_message("Initializing analyzer...");
    let mut analyzer = Analyzer::new();

    progress.set_message("Initializing validator...");
    let validator = Validator::new().await?;

    // Run platform-specific analysis if requested
    let mut platform_findings = Vec::new();

    if fabric {
        progress.set_message("Running Fabric-specific analysis...");
        let mut fabric_analyzer = FabricAnalyzer::new()?;
        let fabric_result = fabric_analyzer.analyze_chaincode(&path).await?;
        platform_findings.extend(fabric_result.findings);
    }

    if solana {
        progress.set_message("Running Solana-specific analysis...");
        let mut solana_analyzer = SolanaAnalyzer::new()?;
        let solana_result = solana_analyzer.analyze_program(&path).await?;
        platform_findings.extend(solana_result.findings);
    }

    progress.set_message("Starting analysis...");

    // Perform analysis
    let mut results = if path.is_file() {
        vec![analyzer.analyze_file(&path).await?]
    } else {
        analyzer.analyze_directory(&path).await?
    };

    // Add platform-specific findings to the results
    if !platform_findings.is_empty() {
        for result in &mut results {
            result.findings.extend(platform_findings.clone());
        }
    }

    // Run AI validation if enabled
    if ai_validate {
        progress.set_message("Running AI validation...");
        for result in &results {
            // TODO: Integrate validator with results
        }
    }

    progress.finish_with_message("Analysis complete!");

    // Generate report
    let reporter = Reporter::new();
    let report = reporter.generate_report(&results, &config)?;

    // Output results
    if let Some(output_path) = output_file {
        reporter.save_report(&report, &output_path, format).await?;
        println!("📊 Report saved to: {}", output_path.display());
    } else {
        println!("\n{}", report.summary());
    }

    // Print summary
    let total_findings = results.iter().map(|r| r.findings.len()).sum::<usize>();

    let critical_count = results
        .iter()
        .flat_map(|r| &r.findings)
        .filter(|f| f.severity == Severity::Critical)
        .count();

    let high_count = results
        .iter()
        .flat_map(|r| &r.findings)
        .filter(|f| f.severity == Severity::High)
        .count();

    println!("\n{}", style("Summary").bold().green());
    println!("{}", style("━".repeat(50)).dim());
    println!("Total findings: {}", style(total_findings).bold());
    println!("Critical: {}", style(critical_count).red().bold());
    println!("High: {}", style(high_count).yellow().bold());

    let exit_code_val = if exit_code && (critical_count > 0 || high_count > 0) {
        println!("Analysis found critical or high severity findings. Exiting with code 1.");
        1
    } else {
        0
    };

    Ok(exit_code_val)
}

async fn validate_command(
    path: PathBuf,
    consensus: bool,
    consensus_level: Option<ConsensusLevel>,
    realtime: bool,
    check_deps: bool,
    determinism: bool,
    output_file: Option<PathBuf>,
    format: OutputFormat,
    quiet: bool,
) -> Result<()> {
    println!("{}", style("🔐 Dependency Validation").bold().cyan());
    println!("{}", style("━".repeat(50)).dim());

    let validator = Validator::new().await?;

    // TODO: Implement validation logic

    Ok(())
}

async fn report_command(
    input: PathBuf,
    format: ReportFormat,
    template: String,
    remediation: bool,
    examples: bool,
    output_file: PathBuf,
    quiet: bool,
) -> Result<()> {
    if !quiet {
        println!("{}", style("📊 Report Generation").bold().cyan());
        println!("{}", style("━".repeat(50)).dim());
    }

    let reporter = Reporter::new();

    // Load report from JSON file
    let content = tokio::fs::read_to_string(&input).await?;
    let report: Report = serde_json::from_str(&content)
        .map_err(|e| ChainGuardError::Report(format!("Failed to parse report: {}", e)))?;

    // Save report in requested format
    let output_format = match format {
        ReportFormat::Html => OutputFormat::Html,
        ReportFormat::Json => OutputFormat::Json,
        ReportFormat::Markdown => OutputFormat::Markdown,
        ReportFormat::Pdf => OutputFormat::Pdf,
        ReportFormat::Xml => OutputFormat::Xml,
        ReportFormat::Csv => OutputFormat::Csv,
        ReportFormat::Sarif => OutputFormat::Sarif,
    };

    reporter
        .save_report(&report, &output_file, output_format)
        .await?;

    if !quiet {
        println!("✅ Report generated: {}", output_file.display());
    }

    Ok(())
}

async fn init_command(
    config_path: PathBuf,
    platform: Option<String>,
    examples: bool,
    force: bool,
) -> Result<()> {
    println!(
        "{}",
        style("⚙️  Configuration Initialization").bold().cyan()
    );
    println!("{}", style("━".repeat(50)).dim());

    if config_path.exists() && !force {
        eprintln!(
            "{}",
            style("Configuration file already exists. Use --force to overwrite.").red()
        );
        return Ok(());
    }

    let config = AnalysisConfig::default();
    let content =
        toml::to_string_pretty(&config).map_err(|e| ChainGuardError::Config(e.to_string()))?;

    tokio::fs::write(&config_path, content).await?;

    println!("✅ Configuration file created: {}", config_path.display());

    Ok(())
}

async fn history_command(
    limit: usize,
    filter: Option<String>,
    detailed: bool,
    export: Option<PathBuf>,
    format: OutputFormat,
) -> Result<()> {
    println!("{}", style("📜 Analysis History").bold().cyan());
    println!("{}", style("━".repeat(50)).dim());

    // TODO: Implement history tracking

    Ok(())
}

async fn scan_command(
    path: PathBuf,
    fabric: bool,
    solana: bool,
    severity: Severity,
    output_file: Option<PathBuf>,
    format: OutputFormat,
    quiet: bool,
) -> Result<i32> {
    if !quiet {
        println!("{}", style("🔍 Quick Security Scan").bold().cyan());
        println!("{}", style("━".repeat(50)).dim());
    }

    let progress = ProgressBar::new_spinner();
    progress.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );

    progress.set_message("Initializing scanner...");
    let mut results: Vec<AnalysisResult> = Vec::new();

    if fabric {
        progress.set_message("Loading Fabric-specific rules...");
        let mut fabric_analyzer = FabricAnalyzer::new()?;

        progress.set_message("Scanning for Fabric vulnerabilities...");
        if path.is_file() {
            let fabric_result = fabric_analyzer.analyze_chaincode(&path).await?;
            results.push(fabric_result.into());
        } else {
            // Scan directory for .go files
            let mut entries = tokio::fs::read_dir(&path).await?;
            while let Some(entry) = entries.next_entry().await? {
                let file_path = entry.path();
                if file_path.extension().map_or(false, |ext| ext == "go") {
                    match fabric_analyzer.analyze_chaincode(&file_path).await {
                        Ok(result) => results.push(result.into()),
                        Err(e) => tracing::warn!("Failed to scan {}: {}", file_path.display(), e),
                    }
                }
            }
        }
    } else if solana {
        progress.set_message("Loading Solana-specific rules...");
        let mut solana_analyzer = SolanaAnalyzer::new()?;

        progress.set_message("Scanning for Solana vulnerabilities...");
        if path.is_file() {
            let solana_result = solana_analyzer.analyze_program(&path).await?;
            results.push(solana_result.into());
        } else {
            // Scan directory for .rs files
            let mut entries = tokio::fs::read_dir(&path).await?;
            while let Some(entry) = entries.next_entry().await? {
                let file_path = entry.path();
                if file_path.extension().map_or(false, |ext| ext == "rs") {
                    match solana_analyzer.analyze_program(&file_path).await {
                        Ok(result) => results.push(result.into()),
                        Err(e) => tracing::warn!("Failed to scan {}: {}", file_path.display(), e),
                    }
                }
            }
        }
    } else {
        // Generic scan
        progress.set_message("Scanning for vulnerabilities...");
        let analyzer = Analyzer::new();

        if path.is_file() {
            results.push(analyzer.quick_scan(&path).await?);
        } else {
            results = analyzer.scan_directory(&path).await?;
        }
    }

    progress.finish_with_message("Scan complete!");

    let findings_count = results
        .iter()
        .flat_map(|r| &r.findings)
        .filter(|f| f.severity >= severity)
        .count();

    // Generate and save report
    if let Some(output_path) = output_file {
        let reporter = Reporter::new();
        let report = reporter.generate_scan_report(&results)?;
        reporter.save_report(&report, &output_path, format).await?;
        println!("📊 Scan report saved to: {}", output_path.display());
    }

    if !quiet {
        println!("\n{}", style("Scan Summary").bold().green());
        println!("{}", style("━".repeat(50)).dim());
        println!(
            "Total vulnerabilities found: {}",
            style(findings_count).bold()
        );
    }

    Ok(if findings_count > 0 { 1 } else { 0 })
}

async fn audit_command(
    path: PathBuf,
    fabric: bool,
    solana: bool,
    standards: Vec<String>,
    framework: Option<String>,
    output_file: Option<PathBuf>,
    format: OutputFormat,
    quiet: bool,
) -> Result<()> {
    if !quiet {
        println!("{}", style("📋 Compliance Audit").bold().cyan());
        println!("{}", style("━".repeat(50)).dim());
    }

    let progress = ProgressBar::new_spinner();
    progress.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );

    progress.set_message("Initializing auditor...");
    let mut auditor = chainguard::auditor::Auditor::new();

    if fabric {
        progress.set_message("Loading Fabric compliance rules...");
        auditor.enable_fabric_compliance();
    }

    if solana {
        progress.set_message("Loading Solana compliance rules...");
        auditor.enable_solana_compliance();
    }

    if !standards.is_empty() {
        progress.set_message("Loading token standards...");
        let mut token_validator = TokenStandardsValidator::new();
        for standard in &standards {
            token_validator.load_standard(standard)?;
        }
    }

    if let Some(ref fw) = framework {
        progress.set_message("Loading framework...");
        auditor.load_framework(fw)?;
    }

    progress.set_message("Running compliance checks...");
    let results = auditor.audit(&path).await?;

    progress.finish_with_message("Audit complete!");

    // Generate and save report
    if let Some(output_path) = output_file {
        let reporter = Reporter::new();
        let report = reporter.generate_audit_report(&results)?;
        reporter.save_report(&report, &output_path, format).await?;
        println!("📊 Audit report saved to: {}", output_path.display());
    }

    if !quiet {
        println!("\n{}", style("Audit Results").bold().green());
        println!("{}", style("━".repeat(50)).dim());
        println!(
            "Compliance Score: {}%",
            style(results.compliance_score).bold()
        );
        println!("Standards Checked: {}", standards.join(", "));
        if let Some(fw) = framework {
            println!("Framework: {}", fw);
        }
    }

    Ok(())
}

async fn benchmark_command(
    path: PathBuf,
    fabric: bool,
    solana: bool,
    throughput: bool,
    storage: bool,
    consensus: bool,
    output_file: Option<PathBuf>,
    format: OutputFormat,
    quiet: bool,
) -> Result<()> {
    if !quiet {
        println!("{}", style("⚡ Performance Benchmark").bold().cyan());
        println!("{}", style("━".repeat(50)).dim());
    }

    let progress = ProgressBar::new_spinner();
    progress.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );

    progress.set_message("Initializing benchmark suite...");
    let mut benchmarker = chainguard::benchmark::Benchmarker::new();

    if fabric {
        benchmarker.enable_fabric_benchmarks();
    }

    if solana {
        benchmarker.enable_solana_benchmarks();
    }

    let mut results = chainguard::benchmark::BenchmarkResults::default();

    if throughput {
        progress.set_message("Analyzing transaction throughput...");
        results.throughput = Some(benchmarker.analyze_throughput(&path).await?);
    }

    if storage {
        progress.set_message("Analyzing storage efficiency...");
        results.storage = Some(benchmarker.analyze_storage(&path).await?);
    }

    if consensus {
        progress.set_message("Analyzing consensus impact...");
        results.consensus = Some(benchmarker.analyze_consensus(&path).await?);
    }

    progress.finish_with_message("Benchmark complete!");

    // Generate and save report
    if let Some(output_path) = output_file {
        let reporter = Reporter::new();
        let report = reporter.generate_benchmark_report(&results)?;
        reporter.save_report(&report, &output_path, format).await?;
        println!("📊 Benchmark report saved to: {}", output_path.display());
    }

    if !quiet {
        println!("\n{}", style("Benchmark Results").bold().green());
        println!("{}", style("━".repeat(50)).dim());

        if let Some(ref t) = results.throughput {
            println!("Transaction Throughput: {} TPS", style(t.tps).bold());
        }
        if let Some(ref s) = results.storage {
            println!("Storage Efficiency: {}%", style(s.efficiency).bold());
        }
        if let Some(ref c) = results.consensus {
            println!("Consensus Overhead: {}ms", style(c.overhead_ms).bold());
        }
    }

    Ok(())
}

async fn optimize_command(
    path: PathBuf,
    platform: String,
    ai_suggestions: bool,
    focus: Vec<String>,
    auto_apply: bool,
    output_file: Option<PathBuf>,
    format: OutputFormat,
    quiet: bool,
) -> Result<()> {
    if !quiet {
        println!("{}", style("🚀 Performance Optimization").bold().cyan());
        println!("{}", style("━".repeat(50)).dim());
    }

    let progress = ProgressBar::new_spinner();
    progress.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );

    progress.set_message("Initializing optimizer...");
    let mut optimizer = chainguard::optimizer::Optimizer::new(&platform)?;

    if ai_suggestions {
        progress.set_message("Connecting to AI services...");
        let llm_manager = LLMManager::new().await?;
        optimizer.enable_ai_suggestions(llm_manager);
    }

    if !focus.is_empty() {
        optimizer.set_focus_areas(focus);
    }

    progress.set_message("Analyzing code for optimizations...");
    let suggestions = optimizer.analyze(&path).await?;

    if auto_apply && !suggestions.is_empty() {
        progress.set_message("Applying optimizations...");
        let applied = optimizer.apply_suggestions(&suggestions).await?;
        println!("✅ Applied {} optimizations", applied);
    }

    progress.finish_with_message("Optimization complete!");

    // Generate and save report
    if let Some(output_path) = output_file {
        let reporter = Reporter::new();
        let report = reporter.generate_optimization_report(&suggestions)?;
        reporter.save_report(&report, &output_path, format).await?;
        println!("📊 Optimization report saved to: {}", output_path.display());
    }

    if !quiet {
        println!("\n{}", style("Optimization Summary").bold().green());
        println!("{}", style("━".repeat(50)).dim());
        println!("Total suggestions: {}", style(suggestions.len()).bold());
        println!(
            "Estimated performance gain: {}%",
            style(suggestions.iter().map(|s| s.performance_gain).sum::<f32>()).bold()
        );
    }

    Ok(())
}

async fn auth_command(command: AuthCommands) -> Result<()> {
    use chainguard::auth::AuthManager;
    let mut auth_manager = AuthManager::new()?;

    match command {
        AuthCommands::Set { service, key } => {
            let api_key = if let Some(k) = key {
                k
            } else {
                // Prompt for key
                dialoguer::Password::new()
                    .with_prompt(&format!("Enter API key for {}", service))
                    .interact()?
            };

            auth_manager.set_api_key(&service, &api_key).await?;
            println!("✅ API key for {} saved successfully", service);
        }

        AuthCommands::Remove { service } => {
            auth_manager.remove_api_key(&service).await?;
            println!("✅ API key for {} removed", service);
        }

        AuthCommands::List => {
            let services = auth_manager.list_services().await?;
            println!("{}", style("Configured Services").bold().cyan());
            println!("{}", style("━".repeat(50)).dim());
            for service in services {
                println!("  • {}", service);
            }
        }

        AuthCommands::Test { service } => {
            if let Some(svc) = service {
                println!("Testing connection to {}...", svc);
                match auth_manager.test_connection(&svc).await {
                    Ok(_) => println!("✅ {} connection successful", svc),
                    Err(e) => println!("❌ {} connection failed: {}", svc, e),
                }
            } else {
                // Test all services
                let services = auth_manager.list_services().await?;
                for svc in services {
                    println!("Testing {}...", svc);
                    match auth_manager.test_connection(&svc).await {
                        Ok(_) => println!("  ✅ Success"),
                        Err(e) => println!("  ❌ Failed: {}", e),
                    }
                }
            }
        }
    }

    Ok(())
}

async fn rules_command(command: RulesCommands) -> Result<()> {
    use chainguard::rules::RuleManager;
    let mut rule_manager = RuleManager::new()?;

    match command {
        RulesCommands::List { category, all } => {
            let rules = rule_manager.list_rules(category.as_deref(), all)?;

            println!("{}", style("Available Rules").bold().cyan());
            println!("{}", style("━".repeat(50)).dim());

            for rule in rules {
                let status = if rule.enabled { "✓" } else { "✗" };
                let status_color = if rule.enabled {
                    style(status).green()
                } else {
                    style(status).red()
                };

                println!(
                    "{} {} - {} [{}]",
                    status_color,
                    style(&rule.id).bold(),
                    rule.description,
                    style(&rule.category).dim()
                );
            }
        }

        RulesCommands::Enable { rule } => {
            let count = rule_manager.enable_rule(&rule)?;
            println!("✅ Enabled {} rule(s)", count);
        }

        RulesCommands::Disable { rule } => {
            let count = rule_manager.disable_rule(&rule)?;
            println!("✅ Disabled {} rule(s)", count);
        }

        RulesCommands::Import { path, validate } => {
            if validate {
                println!("Validating rules...");
                rule_manager.validate_rules_file(&path)?;
            }

            let count = rule_manager.import_rules(&path)?;
            println!("✅ Imported {} custom rule(s)", count);
        }

        RulesCommands::Export { path, custom_only } => {
            rule_manager.export_rules(&path, custom_only)?;
            println!("✅ Rules exported to: {}", path.display());
        }
    }

    Ok(())
}

async fn interactive_command(path: Option<PathBuf>, ai_assist: bool) -> Result<()> {
    use chainguard::interactive::InteractiveSession;

    println!("{}", style("🎯 ChainGuard Interactive Mode").bold().cyan());
    println!("{}", style("━".repeat(50)).dim());
    println!("Type 'help' for available commands, 'exit' to quit");
    println!();

    let mut session = InteractiveSession::new(ai_assist)?;

    if let Some(p) = path {
        session.set_working_directory(p)?;
    }

    session.run().await?;

    Ok(())
}

async fn load_config(path: &PathBuf) -> Result<AnalysisConfig> {
    let content = tokio::fs::read_to_string(path).await?;

    let config = if path
        .extension()
        .map_or(false, |ext| ext == "yaml" || ext == "yml")
    {
        serde_yaml::from_str(&content).map_err(|e| ChainGuardError::Config(e.to_string()))?
    } else if path.extension().map_or(false, |ext| ext == "json") {
        serde_json::from_str(&content).map_err(|e| ChainGuardError::Config(e.to_string()))?
    } else {
        toml::from_str(&content).map_err(|e| ChainGuardError::Config(e.to_string()))?
    };

    Ok(config)
}
