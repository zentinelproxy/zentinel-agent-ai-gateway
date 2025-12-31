//! JSON Schema validation for AI API requests.

use jsonschema::{JSONSchema, ValidationError};
use serde_json::Value;
use std::sync::OnceLock;

/// Schema validation result
#[derive(Debug, Clone)]
pub struct SchemaValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
}

impl SchemaValidationResult {
    pub fn valid() -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
        }
    }

    pub fn invalid(errors: Vec<String>) -> Self {
        Self {
            valid: false,
            errors,
        }
    }
}

/// OpenAI Chat Completion request schema
const OPENAI_CHAT_SCHEMA: &str = r#"{
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "OpenAI Chat Completion Request",
    "type": "object",
    "required": ["model", "messages"],
    "properties": {
        "model": {
            "type": "string",
            "minLength": 1
        },
        "messages": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["role", "content"],
                "properties": {
                    "role": {
                        "type": "string",
                        "enum": ["system", "user", "assistant", "tool", "function"]
                    },
                    "content": {
                        "oneOf": [
                            {"type": "string"},
                            {"type": "null"},
                            {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["type"],
                                    "properties": {
                                        "type": {"type": "string"},
                                        "text": {"type": "string"},
                                        "image_url": {"type": "object"}
                                    }
                                }
                            }
                        ]
                    },
                    "name": {"type": "string"},
                    "tool_calls": {"type": "array"},
                    "tool_call_id": {"type": "string"},
                    "function_call": {"type": "object"}
                }
            }
        },
        "max_tokens": {
            "type": "integer",
            "minimum": 1
        },
        "temperature": {
            "type": "number",
            "minimum": 0,
            "maximum": 2
        },
        "top_p": {
            "type": "number",
            "minimum": 0,
            "maximum": 1
        },
        "n": {
            "type": "integer",
            "minimum": 1
        },
        "stream": {"type": "boolean"},
        "stop": {
            "oneOf": [
                {"type": "string"},
                {"type": "array", "items": {"type": "string"}, "maxItems": 4}
            ]
        },
        "presence_penalty": {
            "type": "number",
            "minimum": -2,
            "maximum": 2
        },
        "frequency_penalty": {
            "type": "number",
            "minimum": -2,
            "maximum": 2
        },
        "logit_bias": {
            "type": "object",
            "additionalProperties": {"type": "number"}
        },
        "user": {"type": "string"},
        "tools": {"type": "array"},
        "tool_choice": {},
        "response_format": {"type": "object"},
        "seed": {"type": "integer"}
    },
    "additionalProperties": true
}"#;

/// OpenAI Legacy Completion request schema
const OPENAI_COMPLETION_SCHEMA: &str = r#"{
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "OpenAI Completion Request",
    "type": "object",
    "required": ["model", "prompt"],
    "properties": {
        "model": {
            "type": "string",
            "minLength": 1
        },
        "prompt": {
            "oneOf": [
                {"type": "string"},
                {"type": "array", "items": {"type": "string"}}
            ]
        },
        "max_tokens": {
            "type": "integer",
            "minimum": 1
        },
        "temperature": {
            "type": "number",
            "minimum": 0,
            "maximum": 2
        },
        "top_p": {
            "type": "number",
            "minimum": 0,
            "maximum": 1
        },
        "n": {
            "type": "integer",
            "minimum": 1
        },
        "stream": {"type": "boolean"},
        "logprobs": {
            "type": "integer",
            "minimum": 0,
            "maximum": 5
        },
        "echo": {"type": "boolean"},
        "stop": {
            "oneOf": [
                {"type": "string"},
                {"type": "array", "items": {"type": "string"}, "maxItems": 4}
            ]
        },
        "presence_penalty": {
            "type": "number",
            "minimum": -2,
            "maximum": 2
        },
        "frequency_penalty": {
            "type": "number",
            "minimum": -2,
            "maximum": 2
        },
        "best_of": {
            "type": "integer",
            "minimum": 1
        },
        "logit_bias": {
            "type": "object",
            "additionalProperties": {"type": "number"}
        },
        "user": {"type": "string"}
    },
    "additionalProperties": true
}"#;

/// Anthropic Messages API request schema
const ANTHROPIC_MESSAGES_SCHEMA: &str = r#"{
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Anthropic Messages Request",
    "type": "object",
    "required": ["model", "max_tokens", "messages"],
    "properties": {
        "model": {
            "type": "string",
            "minLength": 1
        },
        "max_tokens": {
            "type": "integer",
            "minimum": 1
        },
        "messages": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["role", "content"],
                "properties": {
                    "role": {
                        "type": "string",
                        "enum": ["user", "assistant"]
                    },
                    "content": {
                        "oneOf": [
                            {"type": "string"},
                            {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["type"],
                                    "properties": {
                                        "type": {"type": "string"},
                                        "text": {"type": "string"},
                                        "source": {"type": "object"}
                                    }
                                }
                            }
                        ]
                    }
                }
            }
        },
        "system": {
            "oneOf": [
                {"type": "string"},
                {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["type", "text"],
                        "properties": {
                            "type": {"type": "string"},
                            "text": {"type": "string"},
                            "cache_control": {"type": "object"}
                        }
                    }
                }
            ]
        },
        "temperature": {
            "type": "number",
            "minimum": 0,
            "maximum": 1
        },
        "top_p": {
            "type": "number",
            "minimum": 0,
            "maximum": 1
        },
        "top_k": {
            "type": "integer",
            "minimum": 0
        },
        "stream": {"type": "boolean"},
        "stop_sequences": {
            "type": "array",
            "items": {"type": "string"}
        },
        "metadata": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string"}
            }
        },
        "tools": {"type": "array"},
        "tool_choice": {"type": "object"}
    },
    "additionalProperties": true
}"#;

// Compiled schemas (cached)
static OPENAI_CHAT_COMPILED: OnceLock<JSONSchema> = OnceLock::new();
static OPENAI_COMPLETION_COMPILED: OnceLock<JSONSchema> = OnceLock::new();
static ANTHROPIC_MESSAGES_COMPILED: OnceLock<JSONSchema> = OnceLock::new();

fn get_openai_chat_schema() -> &'static JSONSchema {
    OPENAI_CHAT_COMPILED.get_or_init(|| {
        let schema: Value = serde_json::from_str(OPENAI_CHAT_SCHEMA).unwrap();
        JSONSchema::compile(&schema).unwrap()
    })
}

fn get_openai_completion_schema() -> &'static JSONSchema {
    OPENAI_COMPLETION_COMPILED.get_or_init(|| {
        let schema: Value = serde_json::from_str(OPENAI_COMPLETION_SCHEMA).unwrap();
        JSONSchema::compile(&schema).unwrap()
    })
}

fn get_anthropic_messages_schema() -> &'static JSONSchema {
    ANTHROPIC_MESSAGES_COMPILED.get_or_init(|| {
        let schema: Value = serde_json::from_str(ANTHROPIC_MESSAGES_SCHEMA).unwrap();
        JSONSchema::compile(&schema).unwrap()
    })
}

fn format_validation_errors<'a>(errors: impl Iterator<Item = ValidationError<'a>>) -> Vec<String> {
    errors
        .map(|e| {
            let path = e.instance_path.to_string();
            if path.is_empty() {
                e.to_string()
            } else {
                format!("{}: {}", path, e)
            }
        })
        .collect()
}

/// Validate an OpenAI chat completion request
pub fn validate_openai_chat(body: &str) -> SchemaValidationResult {
    let value: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return SchemaValidationResult::invalid(vec![format!("Invalid JSON: {}", e)]);
        }
    };

    let schema = get_openai_chat_schema();
    let result = schema.validate(&value);

    match result {
        Ok(_) => SchemaValidationResult::valid(),
        Err(errors) => SchemaValidationResult::invalid(format_validation_errors(errors)),
    }
}

/// Validate an OpenAI legacy completion request
pub fn validate_openai_completion(body: &str) -> SchemaValidationResult {
    let value: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return SchemaValidationResult::invalid(vec![format!("Invalid JSON: {}", e)]);
        }
    };

    let schema = get_openai_completion_schema();
    let result = schema.validate(&value);

    match result {
        Ok(_) => SchemaValidationResult::valid(),
        Err(errors) => SchemaValidationResult::invalid(format_validation_errors(errors)),
    }
}

/// Validate an Anthropic messages request
pub fn validate_anthropic_messages(body: &str) -> SchemaValidationResult {
    let value: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return SchemaValidationResult::invalid(vec![format!("Invalid JSON: {}", e)]);
        }
    };

    let schema = get_anthropic_messages_schema();
    let result = schema.validate(&value);

    match result {
        Ok(_) => SchemaValidationResult::valid(),
        Err(errors) => SchemaValidationResult::invalid(format_validation_errors(errors)),
    }
}

/// Validate request body based on provider, auto-detecting the request type
pub fn validate_request(provider: super::AiProvider, body: &str) -> SchemaValidationResult {
    let value: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return SchemaValidationResult::invalid(vec![format!("Invalid JSON: {}", e)]);
        }
    };

    match provider {
        super::AiProvider::OpenAI | super::AiProvider::Azure => {
            // Detect if it's chat or legacy completion
            if value.get("messages").is_some() {
                validate_openai_chat(body)
            } else if value.get("prompt").is_some() {
                validate_openai_completion(body)
            } else {
                SchemaValidationResult::invalid(vec![
                    "Missing required field: 'messages' or 'prompt'".to_string(),
                ])
            }
        }
        super::AiProvider::Anthropic => validate_anthropic_messages(body),
        super::AiProvider::Unknown => {
            // Try to detect format and validate
            if value.get("messages").is_some() {
                if value.get("max_tokens").is_some()
                    && !value
                        .get("model")
                        .is_some_and(|m| m.as_str().is_some_and(|s| s.starts_with("gpt")))
                {
                    // Likely Anthropic (requires max_tokens)
                    validate_anthropic_messages(body)
                } else {
                    validate_openai_chat(body)
                }
            } else if value.get("prompt").is_some() {
                validate_openai_completion(body)
            } else {
                SchemaValidationResult::invalid(vec![
                    "Unable to determine request format".to_string()
                ])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_openai_chat() {
        let body = r#"{
            "model": "gpt-4",
            "messages": [
                {"role": "user", "content": "Hello"}
            ]
        }"#;
        let result = validate_openai_chat(body);
        assert!(result.valid, "Errors: {:?}", result.errors);
    }

    #[test]
    fn test_openai_chat_missing_model() {
        let body = r#"{
            "messages": [
                {"role": "user", "content": "Hello"}
            ]
        }"#;
        let result = validate_openai_chat(body);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("model")));
    }

    #[test]
    fn test_openai_chat_missing_messages() {
        let body = r#"{
            "model": "gpt-4"
        }"#;
        let result = validate_openai_chat(body);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("messages")));
    }

    #[test]
    fn test_openai_chat_empty_messages() {
        let body = r#"{
            "model": "gpt-4",
            "messages": []
        }"#;
        let result = validate_openai_chat(body);
        assert!(!result.valid);
    }

    #[test]
    fn test_openai_chat_invalid_role() {
        let body = r#"{
            "model": "gpt-4",
            "messages": [
                {"role": "invalid_role", "content": "Hello"}
            ]
        }"#;
        let result = validate_openai_chat(body);
        assert!(!result.valid);
    }

    #[test]
    fn test_openai_chat_invalid_temperature() {
        let body = r#"{
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "Hi"}],
            "temperature": 5.0
        }"#;
        let result = validate_openai_chat(body);
        assert!(!result.valid);
    }

    #[test]
    fn test_valid_openai_completion() {
        let body = r#"{
            "model": "gpt-3.5-turbo-instruct",
            "prompt": "Hello, world"
        }"#;
        let result = validate_openai_completion(body);
        assert!(result.valid, "Errors: {:?}", result.errors);
    }

    #[test]
    fn test_valid_anthropic_messages() {
        let body = r#"{
            "model": "claude-3-opus-20240229",
            "max_tokens": 1024,
            "messages": [
                {"role": "user", "content": "Hello"}
            ]
        }"#;
        let result = validate_anthropic_messages(body);
        assert!(result.valid, "Errors: {:?}", result.errors);
    }

    #[test]
    fn test_anthropic_missing_max_tokens() {
        let body = r#"{
            "model": "claude-3-opus-20240229",
            "messages": [
                {"role": "user", "content": "Hello"}
            ]
        }"#;
        let result = validate_anthropic_messages(body);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("max_tokens")));
    }

    #[test]
    fn test_anthropic_invalid_role() {
        let body = r#"{
            "model": "claude-3-opus-20240229",
            "max_tokens": 1024,
            "messages": [
                {"role": "system", "content": "Hello"}
            ]
        }"#;
        let result = validate_anthropic_messages(body);
        assert!(!result.valid);
    }

    #[test]
    fn test_anthropic_with_system() {
        let body = r#"{
            "model": "claude-3-opus-20240229",
            "max_tokens": 1024,
            "system": "You are a helpful assistant",
            "messages": [
                {"role": "user", "content": "Hello"}
            ]
        }"#;
        let result = validate_anthropic_messages(body);
        assert!(result.valid, "Errors: {:?}", result.errors);
    }

    #[test]
    fn test_invalid_json() {
        let body = "not valid json";
        let result = validate_openai_chat(body);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("Invalid JSON")));
    }

    #[test]
    fn test_validate_request_auto_detect() {
        // OpenAI chat
        let openai_chat = r#"{"model": "gpt-4", "messages": [{"role": "user", "content": "Hi"}]}"#;
        let result = validate_request(super::super::AiProvider::Unknown, openai_chat);
        assert!(result.valid, "Errors: {:?}", result.errors);

        // Anthropic
        let anthropic = r#"{"model": "claude-3-opus", "max_tokens": 100, "messages": [{"role": "user", "content": "Hi"}]}"#;
        let result = validate_request(super::super::AiProvider::Anthropic, anthropic);
        assert!(result.valid, "Errors: {:?}", result.errors);
    }
}
