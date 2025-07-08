use std::path::Path;
use std::process::Command;

#[test]
fn test_cli_analyze_fabric() {
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "analyze",
            "examples/vulnerable_chaincode.go",
            "--fabric",
        ])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        println!("STDOUT: {}", stdout);
        println!("STDERR: {}", stderr);
        panic!("Command failed with exit code: {:?}", output.status.code());
    }

    assert!(
        stdout.contains("Analysis complete") || stdout.contains("ShieldContract Analysis Report"),
        "Should complete analysis"
    );
    assert!(stdout.contains("Total findings"), "Should show findings");
}

#[test]
fn test_cli_analyze_solana() {
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "analyze",
            "examples/vulnerable_solana_program.rs.example",
            "--solana",
        ])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        println!("STDOUT: {}", stdout);
        println!("STDERR: {}", stderr);
        panic!("Command failed with exit code: {:?}", output.status.code());
    }

    assert!(
        stdout.contains("Analysis complete") || stdout.contains("ShieldContract Analysis Report"),
        "Should complete analysis"
    );
    assert!(stdout.contains("Total findings"), "Should show findings");
}

#[test]
fn test_cli_scan_command() {
    let output = Command::new("cargo")
        .args(["run", "--", "scan", "examples/"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        println!("STDOUT: {}", stdout);
        println!("STDERR: {}", stderr);
        panic!("Command failed with exit code: {:?}", output.status.code());
    }

    assert!(
        stdout.contains("Scan complete") || stdout.contains("Quick Security Scan"),
        "Should complete scan"
    );
}

#[test]
fn test_cli_help() {
    let output = Command::new("cargo")
        .args(["run", "--", "--help"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        println!("STDOUT: {}", stdout);
        println!("STDERR: {}", stderr);
        panic!(
            "Help command failed with exit code: {:?}",
            output.status.code()
        );
    }

    assert!(
        stdout.contains("ShieldContract") || stdout.contains("shieldcontract"),
        "Should show help text"
    );
    assert!(stdout.contains("analyze"), "Should list analyze command");
    assert!(stdout.contains("scan"), "Should list scan command");
}

#[test]
fn test_cli_version() {
    let output = Command::new("cargo")
        .args(["run", "--", "--version"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success(), "Version command should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("shieldcontract"), "Should show version");
}

#[test]
fn test_cli_invalid_file() {
    let output = Command::new("cargo")
        .args(["run", "--", "analyze", "nonexistent.go"])
        .output()
        .expect("Failed to execute command");

    // Should fail with non-zero exit code
    assert!(!output.status.success(), "Should fail for nonexistent file");
}

#[test]
fn test_cli_json_output() {
    use tempfile::NamedTempFile;

    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let temp_path = temp_file.path().to_str().unwrap();

    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "analyze",
            "examples/vulnerable_chaincode.go",
            "-o",
            "json",
            "--output-file",
            temp_path,
        ])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success(), "Command should succeed");
    assert!(
        Path::new(temp_path).exists(),
        "Output file should be created"
    );

    // Verify JSON content
    let content = std::fs::read_to_string(temp_path).expect("Failed to read output file");
    assert!(
        content.contains("\"findings\""),
        "JSON should contain findings"
    );
}
