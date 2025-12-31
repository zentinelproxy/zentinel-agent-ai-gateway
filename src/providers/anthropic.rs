//! Anthropic API request parsing.

use super::{AiProvider, AiRequest, Message};
use serde::Deserialize;

/// Anthropic messages API request format
#[derive(Debug, Deserialize)]
struct AnthropicRequest {
    model: Option<String>,
    messages: Option<Vec<AnthropicMessage>>,
    max_tokens: Option<u32>,
    system: Option<AnthropicSystem>,
    // Legacy completion API
    prompt: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnthropicMessage {
    role: String,
    content: AnthropicContent,
}

/// System can be a string or an array of content blocks
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AnthropicSystem {
    Text(String),
    Blocks(Vec<AnthropicContentBlock>),
}

impl AnthropicSystem {
    fn as_text(&self) -> String {
        match self {
            AnthropicSystem::Text(s) => s.clone(),
            AnthropicSystem::Blocks(blocks) => blocks
                .iter()
                .filter_map(|b| {
                    if b.content_type == "text" {
                        b.text.clone()
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
                .join(" "),
        }
    }
}

/// Content can be a string or an array of content blocks
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AnthropicContent {
    Text(String),
    Blocks(Vec<AnthropicContentBlock>),
}

#[derive(Debug, Deserialize)]
struct AnthropicContentBlock {
    #[serde(rename = "type")]
    content_type: String,
    text: Option<String>,
    // image would be here for vision
}

impl AnthropicContent {
    fn as_text(&self) -> String {
        match self {
            AnthropicContent::Text(s) => s.clone(),
            AnthropicContent::Blocks(blocks) => blocks
                .iter()
                .filter_map(|b| {
                    if b.content_type == "text" {
                        b.text.clone()
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
                .join(" "),
        }
    }
}

/// Parse Anthropic-format request body
pub fn parse_request(body: &str) -> Option<AiRequest> {
    let parsed: AnthropicRequest = serde_json::from_str(body).ok()?;

    let mut messages = Vec::new();
    let mut system_prompt = None;

    // Extract system prompt
    if let Some(sys) = parsed.system {
        system_prompt = Some(sys.as_text());
    }

    // Handle messages API format
    if let Some(msgs) = parsed.messages {
        for msg in msgs {
            let content = msg.content.as_text();
            messages.push(Message {
                role: msg.role,
                content,
            });
        }
    }

    // Handle legacy completion format (Human:/Assistant: format)
    if let Some(prompt) = parsed.prompt {
        // Parse the Human:/Assistant: format
        let parts: Vec<&str> = prompt.split("\n\n").collect();
        for part in parts {
            let part = part.trim();
            if let Some(human_text) = part.strip_prefix("Human:") {
                let content = human_text.trim();
                if !content.is_empty() {
                    messages.push(Message {
                        role: "user".to_string(),
                        content: content.to_string(),
                    });
                }
            } else if let Some(assistant_text) = part.strip_prefix("Assistant:") {
                let content = assistant_text.trim();
                if !content.is_empty() {
                    messages.push(Message {
                        role: "assistant".to_string(),
                        content: content.to_string(),
                    });
                }
            }
        }

        // If no structured messages found, treat whole prompt as user message
        if messages.is_empty() {
            messages.push(Message {
                role: "user".to_string(),
                content: prompt,
            });
        }
    }

    if messages.is_empty() {
        return None;
    }

    Some(AiRequest {
        provider: AiProvider::Anthropic,
        model: parsed.model,
        messages,
        max_tokens: parsed.max_tokens,
        system_prompt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_messages_api() {
        let body = r#"{
            "model": "claude-3-opus-20240229",
            "messages": [
                {"role": "user", "content": "Hello, Claude!"}
            ],
            "max_tokens": 1024
        }"#;

        let req = parse_request(body).unwrap();
        assert_eq!(req.model, Some("claude-3-opus-20240229".to_string()));
        assert_eq!(req.messages.len(), 1);
        assert_eq!(req.messages[0].role, "user");
        assert_eq!(req.messages[0].content, "Hello, Claude!");
        assert_eq!(req.max_tokens, Some(1024));
    }

    #[test]
    fn test_parse_with_system_prompt() {
        let body = r#"{
            "model": "claude-3-sonnet-20240229",
            "system": "You are a helpful assistant.",
            "messages": [
                {"role": "user", "content": "Hi!"}
            ],
            "max_tokens": 500
        }"#;

        let req = parse_request(body).unwrap();
        assert_eq!(
            req.system_prompt,
            Some("You are a helpful assistant.".to_string())
        );
    }

    #[test]
    fn test_parse_system_as_blocks() {
        let body = r#"{
            "model": "claude-3-sonnet-20240229",
            "system": [
                {"type": "text", "text": "You are helpful."},
                {"type": "text", "text": "Be concise."}
            ],
            "messages": [
                {"role": "user", "content": "Hi!"}
            ],
            "max_tokens": 500
        }"#;

        let req = parse_request(body).unwrap();
        assert_eq!(
            req.system_prompt,
            Some("You are helpful. Be concise.".to_string())
        );
    }

    #[test]
    fn test_parse_content_blocks() {
        let body = r#"{
            "model": "claude-3-opus-20240229",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "What's in this image?"},
                        {"type": "image", "source": {"type": "base64", "data": "..."}}
                    ]
                }
            ],
            "max_tokens": 1024
        }"#;

        let req = parse_request(body).unwrap();
        assert_eq!(req.messages[0].content, "What's in this image?");
    }

    #[test]
    fn test_parse_legacy_completion() {
        let body = r#"{
            "model": "claude-2.1",
            "prompt": "\n\nHuman: Hello!\n\nAssistant:",
            "max_tokens": 100
        }"#;

        let req = parse_request(body).unwrap();
        assert_eq!(req.messages.len(), 1);
        assert_eq!(req.messages[0].role, "user");
        assert_eq!(req.messages[0].content, "Hello!");
    }

    #[test]
    fn test_parse_multi_turn() {
        let body = r#"{
            "model": "claude-3-opus-20240229",
            "messages": [
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi there!"},
                {"role": "user", "content": "How are you?"}
            ],
            "max_tokens": 1024
        }"#;

        let req = parse_request(body).unwrap();
        assert_eq!(req.messages.len(), 3);
        assert_eq!(req.messages[0].role, "user");
        assert_eq!(req.messages[1].role, "assistant");
        assert_eq!(req.messages[2].role, "user");
    }
}
