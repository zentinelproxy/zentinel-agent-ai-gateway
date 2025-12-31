//! OpenAI API request parsing.

use super::{AiProvider, AiRequest, Message};
use serde::Deserialize;

/// OpenAI chat completion request format
#[derive(Debug, Deserialize)]
struct OpenAiChatRequest {
    model: Option<String>,
    messages: Option<Vec<OpenAiMessage>>,
    max_tokens: Option<u32>,
    // Legacy completions API
    prompt: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenAiMessage {
    role: String,
    content: OpenAiContent,
}

/// Content can be a string or an array (for vision models)
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OpenAiContent {
    Text(String),
    Parts(Vec<OpenAiContentPart>),
}

#[derive(Debug, Deserialize)]
struct OpenAiContentPart {
    #[serde(rename = "type")]
    content_type: String,
    text: Option<String>,
    // image_url would be here for vision
}

impl OpenAiContent {
    fn as_text(&self) -> String {
        match self {
            OpenAiContent::Text(s) => s.clone(),
            OpenAiContent::Parts(parts) => parts
                .iter()
                .filter_map(|p| {
                    if p.content_type == "text" {
                        p.text.clone()
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
                .join(" "),
        }
    }
}

/// Parse OpenAI-format request body
pub fn parse_request(body: &str) -> Option<AiRequest> {
    let parsed: OpenAiChatRequest = serde_json::from_str(body).ok()?;

    let mut messages = Vec::new();
    let mut system_prompt = None;

    // Handle chat completions format
    if let Some(msgs) = parsed.messages {
        for msg in msgs {
            let content = msg.content.as_text();
            if msg.role == "system" {
                system_prompt = Some(content.clone());
            }
            messages.push(Message {
                role: msg.role,
                content,
            });
        }
    }

    // Handle legacy completions format
    if let Some(prompt) = parsed.prompt {
        messages.push(Message {
            role: "user".to_string(),
            content: prompt,
        });
    }

    if messages.is_empty() {
        return None;
    }

    Some(AiRequest {
        provider: AiProvider::OpenAI,
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
    fn test_parse_chat_completion() {
        let body = r#"{
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Hello!"}
            ],
            "max_tokens": 100
        }"#;

        let req = parse_request(body).unwrap();
        assert_eq!(req.model, Some("gpt-4".to_string()));
        assert_eq!(req.messages.len(), 2);
        assert_eq!(req.max_tokens, Some(100));
        assert_eq!(
            req.system_prompt,
            Some("You are a helpful assistant.".to_string())
        );
    }

    #[test]
    fn test_parse_legacy_completion() {
        let body = r#"{
            "model": "gpt-3.5-turbo-instruct",
            "prompt": "Say hello",
            "max_tokens": 50
        }"#;

        let req = parse_request(body).unwrap();
        assert_eq!(req.model, Some("gpt-3.5-turbo-instruct".to_string()));
        assert_eq!(req.messages.len(), 1);
        assert_eq!(req.messages[0].content, "Say hello");
    }

    #[test]
    fn test_parse_multipart_content() {
        let body = r#"{
            "model": "gpt-4-vision-preview",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "What's in this image?"},
                        {"type": "image_url", "image_url": {"url": "http://example.com/img.png"}}
                    ]
                }
            ]
        }"#;

        let req = parse_request(body).unwrap();
        assert_eq!(req.messages[0].content, "What's in this image?");
    }
}
