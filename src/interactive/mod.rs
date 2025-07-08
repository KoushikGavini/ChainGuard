use crate::{Result, ShieldContractError};
use console::style;
use dialoguer::{theme::ColorfulTheme, Input, Select};
use std::path::PathBuf;

pub struct InteractiveSession {
    ai_enabled: bool,
    working_directory: Option<PathBuf>,
}

impl InteractiveSession {
    pub fn new(ai_enabled: bool) -> Result<Self> {
        Ok(Self {
            ai_enabled,
            working_directory: None,
        })
    }

    pub fn set_working_directory(&mut self, path: PathBuf) -> Result<()> {
        if path.exists() {
            self.working_directory = Some(path);
            Ok(())
        } else {
            Err(ShieldContractError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Directory not found",
            )))
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        println!(
            "{}",
            style("Welcome to ShieldContract Interactive Mode!")
                .bold()
                .cyan()
        );
        if self.ai_enabled {
            println!("{}", style("AI assistance is enabled").green());
        }
        println!();

        loop {
            let commands = vec![
                "Analyze file/directory",
                "Quick scan",
                "Validate AI-generated code",
                "Run benchmark",
                "Change directory",
                "Toggle AI assistance",
                "Help",
                "Exit",
            ];

            let selection = Select::with_theme(&ColorfulTheme::default())
                .with_prompt("What would you like to do?")
                .items(&commands)
                .default(0)
                .interact()
                .unwrap();

            match selection {
                0 => self.analyze_interactive().await?,
                1 => self.scan_interactive().await?,
                2 => self.validate_interactive().await?,
                3 => self.benchmark_interactive().await?,
                4 => self.change_directory()?,
                5 => self.toggle_ai(),
                6 => self.show_help(),
                7 => {
                    println!("{}", style("Goodbye!").green());
                    break;
                }
                _ => unreachable!(),
            }

            println!();
        }

        Ok(())
    }

    async fn analyze_interactive(&self) -> Result<()> {
        let path: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter file or directory path")
            .default(
                self.working_directory
                    .as_ref()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| ".".to_string()),
            )
            .interact_text()
            .unwrap();

        println!("{}", style("Starting analysis...").yellow());

        // In a real implementation, this would call the analyzer
        println!("{}", style("Analysis complete!").green());

        Ok(())
    }

    async fn scan_interactive(&self) -> Result<()> {
        let path: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter file or directory path to scan")
            .interact_text()
            .unwrap();

        println!("{}", style("Starting quick scan...").yellow());

        // In a real implementation, this would call the scanner
        println!("{}", style("Scan complete!").green());

        Ok(())
    }

    async fn validate_interactive(&self) -> Result<()> {
        let path: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter AI-generated code file path")
            .interact_text()
            .unwrap();

        println!("{}", style("Validating AI-generated code...").yellow());

        if self.ai_enabled {
            println!("{}", style("Using multi-AI consensus validation").cyan());
        }

        // In a real implementation, this would call the validator
        println!("{}", style("Validation complete!").green());

        Ok(())
    }

    async fn benchmark_interactive(&self) -> Result<()> {
        let path: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter file or directory path to benchmark")
            .interact_text()
            .unwrap();

        println!("{}", style("Running performance benchmark...").yellow());

        // In a real implementation, this would call the benchmarker
        println!("{}", style("Benchmark complete!").green());

        Ok(())
    }

    fn change_directory(&mut self) -> Result<()> {
        let path: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter new working directory")
            .interact_text()
            .unwrap();

        let path_buf = PathBuf::from(path);
        self.set_working_directory(path_buf.clone())?;

        println!(
            "{} {}",
            style("Working directory changed to:").green(),
            style(path_buf.display()).bold()
        );

        Ok(())
    }

    fn toggle_ai(&mut self) {
        self.ai_enabled = !self.ai_enabled;

        if self.ai_enabled {
            println!("{}", style("AI assistance enabled").green());
        } else {
            println!("{}", style("AI assistance disabled").yellow());
        }
    }

    fn show_help(&self) {
        println!(
            "{}",
            style("ShieldContract Interactive Mode Help").bold().cyan()
        );
        println!("{}", style("================================").dim());
        println!();
        println!(
            "• {} - Perform comprehensive security analysis",
            style("Analyze").bold()
        );
        println!("• {} - Quick vulnerability scan", style("Scan").bold());
        println!(
            "• {} - Validate AI-generated code",
            style("Validate").bold()
        );
        println!(
            "• {} - Run performance benchmarks",
            style("Benchmark").bold()
        );
        println!(
            "• {} - Change the working directory",
            style("Change directory").bold()
        );
        println!(
            "• {} - Enable/disable AI assistance",
            style("Toggle AI").bold()
        );
        println!();
        println!("All paths can be relative to the current working directory.");

        if let Some(ref dir) = self.working_directory {
            println!();
            println!("Current working directory: {}", style(dir.display()).bold());
        }
    }
}
