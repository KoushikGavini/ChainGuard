use chainguard::fabric::FabricAnalyzer;
use std::path::Path;

#[tokio::test]
async fn test_fabric_analyzer_detects_nondeterminism() {
    let mut analyzer = FabricAnalyzer::new().expect("Failed to create analyzer");
    let path = Path::new("examples/vulnerable_chaincode.go");
    
    let result = analyzer.analyze_chaincode(path).await.expect("Analysis failed");
    
    // Should detect nondeterminism issues
    let nondeterminism_findings: Vec<_> = result.findings.iter()
        .filter(|f| f.category.contains("Nondeterminism"))
        .collect();
    
    assert!(!nondeterminism_findings.is_empty(), "Should detect nondeterminism issues");
    assert!(nondeterminism_findings.iter().any(|f| f.id == "FABRIC-ND-001"));
}

#[tokio::test]
async fn test_fabric_analyzer_detects_dos_vulnerabilities() {
    let mut analyzer = FabricAnalyzer::new().expect("Failed to create analyzer");
    let path = Path::new("examples/vulnerable_chaincode.go");
    
    let result = analyzer.analyze_chaincode(path).await.expect("Analysis failed");
    
    // Should detect DoS vulnerabilities
    let dos_findings: Vec<_> = result.findings.iter()
        .filter(|f| f.category.contains("DoS"))
        .collect();
    
    assert!(!dos_findings.is_empty(), "Should detect DoS vulnerabilities");
}

#[tokio::test]
async fn test_fabric_analyzer_calculates_scores() {
    let mut analyzer = FabricAnalyzer::new().expect("Failed to create analyzer");
    let path = Path::new("examples/vulnerable_chaincode.go");
    
    let result = analyzer.analyze_chaincode(path).await.expect("Analysis failed");
    
    // Scores should be calculated
    assert!(result.determinism_score >= 0.0 && result.determinism_score <= 100.0);
    assert!(result.security_score >= 0.0 && result.security_score <= 100.0);
    assert!(result.performance_score >= 0.0 && result.performance_score <= 100.0);
    assert!(result.fabric_best_practices_score >= 0.0 && result.fabric_best_practices_score <= 100.0);
}

#[tokio::test] 
async fn test_fabric_analyzer_handles_nonexistent_file() {
    let mut analyzer = FabricAnalyzer::new().expect("Failed to create analyzer");
    let path = Path::new("nonexistent.go");
    
    let result = analyzer.analyze_chaincode(path).await;
    assert!(result.is_err(), "Should fail for nonexistent file");
}

#[tokio::test]
async fn test_fabric_analyzer_empty_file() {
    use tokio::fs;
    
    // Create a temporary empty file
    let temp_file = "test_empty.go";
    fs::write(temp_file, "").await.expect("Failed to create temp file");
    
    let mut analyzer = FabricAnalyzer::new().expect("Failed to create analyzer");
    let path = Path::new(temp_file);
    
    let result = analyzer.analyze_chaincode(path).await;
    
    // Clean up
    fs::remove_file(temp_file).await.ok();
    
    // Should handle empty file gracefully
    assert!(result.is_ok(), "Should handle empty file");
    if let Ok(res) = result {
        assert_eq!(res.findings.len(), 1); // Only missing endorsement policy check
    }
} 