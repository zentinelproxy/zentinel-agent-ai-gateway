//! AI provider detection and request parsing.

pub mod anthropic;
pub mod openai;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Detected AI provider
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AiProvider {
    OpenAI,
    Anthropic,
    Azure,
    #[default]
    Unknown,
}

impl AiProvider {
    /// Get the provider name as a string
    pub fn as_str(&self) -> &'static str {
        match self {
            AiProvider::OpenAI => "openai",
            AiProvider::Anthropic => "anthropic",
            AiProvider::Azure => "azure",
            AiProvider::Unknown => "unknown",
        }
    }
}

/// A message in a conversation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

/// Parsed AI request
#[derive(Debug, Clone)]
pub struct AiRequest {
    pub provider: AiProvider,
    pub model: Option<String>,
    pub messages: Vec<Message>,
    pub max_tokens: Option<u32>,
    pub system_prompt: Option<String>,
}

impl AiRequest {
    /// Get all text content from the request for scanning
    pub fn all_content(&self) -> Vec<&str> {
        let mut content: Vec<&str> = self.messages.iter().map(|m| m.content.as_str()).collect();
        if let Some(ref sys) = self.system_prompt {
            content.push(sys.as_str());
        }
        content
    }

    /// Estimate token count (rough approximation)
    pub fn estimate_tokens(&self) -> u32 {
        let total_chars: usize = self
            .messages
            .iter()
            .map(|m| m.content.len() + m.role.len())
            .sum();

        let system_chars = self.system_prompt.as_ref().map(|s| s.len()).unwrap_or(0);

        // Rough estimate: ~4 characters per token for English
        ((total_chars + system_chars) as f32 / 4.0).ceil() as u32
    }
}

/// Detect provider from request path and headers
pub fn detect_provider(path: &str, headers: &HashMap<String, Vec<String>>) -> AiProvider {
    // Check path patterns
    if path.contains("/openai/deployments/") {
        return AiProvider::Azure;
    }

    if path.starts_with("/v1/chat/completions")
        || path.starts_with("/v1/completions")
        || path.starts_with("/v1/embeddings")
    {
        // Could be OpenAI or Anthropic - check headers
        if headers.contains_key("anthropic-version") || headers.contains_key("x-api-key") {
            // Check if it looks like Anthropic path
            if path.starts_with("/v1/messages") || path.starts_with("/v1/complete") {
                return AiProvider::Anthropic;
            }
        }

        // Check for OpenAI-style auth
        if let Some(auth) = headers.get("authorization") {
            if auth.iter().any(|v| v.starts_with("Bearer sk-")) {
                return AiProvider::OpenAI;
            }
        }

        // Default to OpenAI for these paths
        return AiProvider::OpenAI;
    }

    if path.starts_with("/v1/messages") || path.starts_with("/v1/complete") {
        return AiProvider::Anthropic;
    }

    AiProvider::Unknown
}

/// Parse request body based on detected provider
pub fn parse_request(provider: AiProvider, body: &str) -> Option<AiRequest> {
    match provider {
        AiProvider::OpenAI | AiProvider::Azure => openai::parse_request(body),
        AiProvider::Anthropic => anthropic::parse_request(body),
        AiProvider::Unknown => {
            // Try OpenAI format first, then Anthropic
            openai::parse_request(body).or_else(|| anthropic::parse_request(body))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_openai() {
        let headers = HashMap::new();
        assert_eq!(
            detect_provider("/v1/chat/completions", &headers),
            AiProvider::OpenAI
        );
    }

    #[test]
    fn test_detect_anthropic() {
        let headers = HashMap::new();
        assert_eq!(
            detect_provider("/v1/messages", &headers),
            AiProvider::Anthropic
        );
    }

    #[test]
    fn test_detect_azure() {
        let headers = HashMap::new();
        assert_eq!(
            detect_provider("/openai/deployments/gpt-4/chat/completions", &headers),
            AiProvider::Azure
        );
    }
}
