use shieldcontract::solana::SolanaAnalyzer;
use std::path::Path;

#[tokio::test]
async fn test_solana_analyzer_detects_arithmetic_issues() {
    let mut analyzer = SolanaAnalyzer::new().expect("Failed to create analyzer");
    let path = Path::new("examples/vulnerable_solana_program.rs.example");

    let result = analyzer
        .analyze_program(path)
        .await
        .expect("Analysis failed");

    // Should detect arithmetic issues
    let arithmetic_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category.contains("Arithmetic"))
        .collect();

    assert!(
        !arithmetic_findings.is_empty(),
        "Should detect arithmetic issues"
    );
    assert!(arithmetic_findings.iter().any(|f| f.id == "SOL-ARITH-001"));
}

#[tokio::test]
async fn test_solana_analyzer_detects_account_validation_issues() {
    let mut analyzer = SolanaAnalyzer::new().expect("Failed to create analyzer");
    let path = Path::new("examples/vulnerable_solana_program.rs.example");

    let result = analyzer
        .analyze_program(path)
        .await
        .expect("Analysis failed");

    // Should detect account validation issues
    let account_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category.contains("AccountValidation"))
        .collect();

    assert!(
        !account_findings.is_empty(),
        "Should detect account validation issues"
    );
}

#[tokio::test]
async fn test_solana_analyzer_detects_signer_check_issues() {
    let mut analyzer = SolanaAnalyzer::new().expect("Failed to create analyzer");
    let path = Path::new("examples/vulnerable_solana_program.rs.example");

    let result = analyzer
        .analyze_program(path)
        .await
        .expect("Analysis failed");

    // Should detect signer check issues
    let signer_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category.contains("SignerCheck"))
        .collect();

    assert!(
        !signer_findings.is_empty(),
        "Should detect signer check issues"
    );
}

#[tokio::test]
async fn test_solana_analyzer_calculates_scores() {
    let mut analyzer = SolanaAnalyzer::new().expect("Failed to create analyzer");
    let path = Path::new("examples/vulnerable_solana_program.rs.example");

    let result = analyzer
        .analyze_program(path)
        .await
        .expect("Analysis failed");

    // Scores should be calculated
    assert!(result.security_score >= 0.0 && result.security_score <= 100.0);
    assert!(result.performance_score >= 0.0 && result.performance_score <= 100.0);
    assert!(result.best_practices_score >= 0.0 && result.best_practices_score <= 100.0);
}

#[tokio::test]
async fn test_solana_analyzer_handles_nonexistent_file() {
    let mut analyzer = SolanaAnalyzer::new().expect("Failed to create analyzer");
    let path = Path::new("nonexistent.rs");

    let result = analyzer.analyze_program(path).await;
    assert!(result.is_err(), "Should fail for nonexistent file");
}

#[tokio::test]
async fn test_solana_analyzer_empty_file() {
    use tokio::fs;

    // Create a temporary empty file
    let temp_file = "test_empty.rs";
    fs::write(temp_file, "")
        .await
        .expect("Failed to create temp file");

    let mut analyzer = SolanaAnalyzer::new().expect("Failed to create analyzer");
    let path = Path::new(temp_file);

    let result = analyzer.analyze_program(path).await;

    // Clean up
    fs::remove_file(temp_file).await.ok();

    // Should handle empty file gracefully
    assert!(result.is_ok(), "Should handle empty file");
    if let Ok(res) = result {
        assert_eq!(res.findings.len(), 0); // No findings for empty file
    }
}
