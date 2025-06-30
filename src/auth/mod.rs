use crate::{ChainGuardError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs;

const CONFIG_DIR: &str = ".chainguard";
const AUTH_FILE: &str = "auth.toml";

pub struct AuthManager {
    config_path: PathBuf,
    credentials: HashMap<String, ServiceCredentials>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServiceCredentials {
    service: String,
    api_key: String,
    endpoint: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthConfig {
    credentials: HashMap<String, ServiceCredentials>,
}

impl AuthManager {
    pub fn new() -> Result<Self> {
        let home_dir = dirs::home_dir()
            .ok_or_else(|| ChainGuardError::Auth("Could not find home directory".to_string()))?;

        let config_path = home_dir.join(CONFIG_DIR).join(AUTH_FILE);

        Ok(Self {
            config_path,
            credentials: HashMap::new(),
        })
    }

    pub async fn load(&mut self) -> Result<()> {
        if self.config_path.exists() {
            let content = fs::read_to_string(&self.config_path).await?;
            let config: AuthConfig = toml::from_str(&content).map_err(|e| {
                ChainGuardError::Config(format!("Failed to parse auth config: {}", e))
            })?;

            self.credentials = config.credentials;
        }

        Ok(())
    }

    pub async fn save(&self) -> Result<()> {
        // Create config directory if it doesn't exist
        if let Some(parent) = self.config_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let config = AuthConfig {
            credentials: self.credentials.clone(),
        };

        let content = toml::to_string_pretty(&config).map_err(|e| {
            ChainGuardError::Config(format!("Failed to serialize auth config: {}", e))
        })?;

        fs::write(&self.config_path, content).await?;

        // Set file permissions to 600 (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&self.config_path).await?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            fs::set_permissions(&self.config_path, permissions).await?;
        }

        Ok(())
    }

    pub async fn set_api_key(&mut self, service: &str, api_key: &str) -> Result<()> {
        // Validate service name
        let service_lower = service.to_lowercase();
        let valid_services = vec![
            "chatgpt",
            "claude",
            "gemini",
            "openai",
            "anthropic",
            "google",
        ];

        if !valid_services.contains(&service_lower.as_str()) {
            return Err(ChainGuardError::Auth(format!(
                "Unknown service: {}. Valid services are: {:?}",
                service, valid_services
            )));
        }

        // Validate API key format (basic validation)
        if api_key.trim().is_empty() {
            return Err(ChainGuardError::Auth("API key cannot be empty".to_string()));
        }

        // Set endpoint based on service
        let endpoint = match service_lower.as_str() {
            "chatgpt" | "openai" => Some("https://api.openai.com/v1".to_string()),
            "claude" | "anthropic" => Some("https://api.anthropic.com".to_string()),
            "gemini" | "google" => Some("https://generativelanguage.googleapis.com".to_string()),
            _ => None,
        };

        let credentials = ServiceCredentials {
            service: service_lower.clone(),
            api_key: api_key.to_string(),
            endpoint,
            created_at: chrono::Utc::now(),
        };

        self.credentials.insert(service_lower, credentials);

        // Load existing config to preserve other credentials
        self.load().await.ok();

        // Save updated config
        self.save().await?;

        Ok(())
    }

    pub async fn remove_api_key(&mut self, service: &str) -> Result<()> {
        self.load().await?;

        let service_lower = service.to_lowercase();
        if self.credentials.remove(&service_lower).is_none() {
            return Err(ChainGuardError::Auth(format!(
                "No credentials found for service: {}",
                service
            )));
        }

        self.save().await?;
        Ok(())
    }

    pub async fn get_api_key(&mut self, service: &str) -> Result<String> {
        self.load().await?;

        let service_lower = service.to_lowercase();
        self.credentials
            .get(&service_lower)
            .map(|c| c.api_key.clone())
            .ok_or_else(|| {
                ChainGuardError::Auth(format!("No API key found for service: {}", service))
            })
    }

    pub async fn list_services(&mut self) -> Result<Vec<String>> {
        self.load().await?;
        Ok(self.credentials.keys().cloned().collect())
    }

    pub async fn test_connection(&mut self, service: &str) -> Result<()> {
        let api_key = self.get_api_key(service).await?;

        match service.to_lowercase().as_str() {
            "chatgpt" | "openai" => self.test_openai_connection(&api_key).await,
            "claude" | "anthropic" => self.test_anthropic_connection(&api_key).await,
            "gemini" | "google" => self.test_google_connection(&api_key).await,
            _ => Err(ChainGuardError::Auth(format!(
                "Unknown service: {}",
                service
            ))),
        }
    }

    async fn test_openai_connection(&self, api_key: &str) -> Result<()> {
        let client = reqwest::Client::new();
        let response = client
            .get("https://api.openai.com/v1/models")
            .header("Authorization", format!("Bearer {}", api_key))
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(ChainGuardError::Auth(format!(
                "OpenAI API test failed: {}",
                response.status()
            )))
        }
    }

    async fn test_anthropic_connection(&self, api_key: &str) -> Result<()> {
        let client = reqwest::Client::new();
        let response = client
            .get("https://api.anthropic.com/v1/messages")
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .send()
            .await?;

        // Anthropic returns 405 for GET requests, which is expected
        if response.status().as_u16() == 405 || response.status().is_success() {
            Ok(())
        } else {
            Err(ChainGuardError::Auth(format!(
                "Anthropic API test failed: {}",
                response.status()
            )))
        }
    }

    async fn test_google_connection(&self, api_key: &str) -> Result<()> {
        let client = reqwest::Client::new();
        let response = client
            .get(format!(
                "https://generativelanguage.googleapis.com/v1beta/models?key={}",
                api_key
            ))
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(ChainGuardError::Auth(format!(
                "Google AI API test failed: {}",
                response.status()
            )))
        }
    }

    pub async fn get_credentials(&mut self, service: &str) -> Result<(String, Option<String>)> {
        self.load().await?;

        let service_lower = service.to_lowercase();
        self.credentials
            .get(&service_lower)
            .map(|c| (c.api_key.clone(), c.endpoint.clone()))
            .ok_or_else(|| {
                ChainGuardError::Auth(format!("No credentials found for service: {}", service))
            })
    }
}
