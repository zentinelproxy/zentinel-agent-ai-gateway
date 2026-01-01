//! AI Gateway Agent for Sentinel proxy.
//!
//! Provides comprehensive control over AI API requests including:
//! - Prompt injection detection
//! - PII detection and redaction
//! - Jailbreak attempt detection
//! - Usage control (token limits, cost estimation)
//! - Rate limiting (requests/tokens per minute)
//! - Model validation and routing

pub mod detection;
pub mod providers;
pub mod ratelimit;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use detection::{JailbreakDetector, PiiDetector, PiiType, PromptInjectionDetector};
use providers::{AiProvider, AiRequest};
use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, AuditMetadata, ConfigureEvent, HeaderOp, RequestBodyChunkEvent,
    RequestHeadersEvent,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

/// Action to take when PII is detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PiiAction {
    /// Block the request
    Block,
    /// Redact PII and continue (not yet implemented - requires body modification)
    Redact,
    /// Log only, allow request
    #[default]
    Log,
}

impl std::str::FromStr for PiiAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "block" => Ok(PiiAction::Block),
            "redact" => Ok(PiiAction::Redact),
            "log" => Ok(PiiAction::Log),
            _ => Err(format!("Invalid PII action: {}", s)),
        }
    }
}

/// JSON-serializable configuration for the AI Gateway agent
///
/// Used for parsing configuration from the on_configure() event.
/// Field names use kebab-case to match typical YAML/JSON config style.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AiGatewayConfigJson {
    /// Enable prompt injection detection
    #[serde(default = "default_true")]
    pub prompt_injection_enabled: bool,
    /// Enable PII detection
    #[serde(default = "default_true")]
    pub pii_detection_enabled: bool,
    /// Action to take on PII detection: "block", "redact", or "log"
    #[serde(default)]
    pub pii_action: String,
    /// Enable jailbreak detection
    #[serde(default = "default_true")]
    pub jailbreak_detection_enabled: bool,
    /// Enable JSON schema validation
    #[serde(default)]
    pub schema_validation_enabled: bool,
    /// Maximum tokens per request (None = no limit)
    #[serde(default)]
    pub max_tokens_per_request: Option<u32>,
    /// Add cost estimation headers
    #[serde(default = "default_true")]
    pub add_cost_headers: bool,
    /// Allowed models (empty = allow all)
    #[serde(default)]
    pub allowed_models: Vec<String>,
    /// Block mode (false = detect-only, log but don't block)
    #[serde(default = "default_true")]
    pub block_mode: bool,
    /// Fail open on errors
    #[serde(default)]
    pub fail_open: bool,
    /// Rate limit: requests per minute per client (0 = unlimited)
    #[serde(default)]
    pub rate_limit_requests: u32,
    /// Rate limit: tokens per minute per client (0 = unlimited)
    #[serde(default)]
    pub rate_limit_tokens: u32,
}

fn default_true() -> bool {
    true
}

impl Default for AiGatewayConfigJson {
    fn default() -> Self {
        Self {
            prompt_injection_enabled: true,
            pii_detection_enabled: true,
            pii_action: "log".to_string(),
            jailbreak_detection_enabled: true,
            schema_validation_enabled: false,
            max_tokens_per_request: None,
            add_cost_headers: true,
            allowed_models: Vec::new(),
            block_mode: true,
            fail_open: false,
            rate_limit_requests: 0,
            rate_limit_tokens: 0,
        }
    }
}

impl From<AiGatewayConfigJson> for AiGatewayConfig {
    fn from(json: AiGatewayConfigJson) -> Self {
        let pii_action = json
            .pii_action
            .parse::<PiiAction>()
            .unwrap_or(PiiAction::Log);
        Self {
            prompt_injection_enabled: json.prompt_injection_enabled,
            pii_detection_enabled: json.pii_detection_enabled,
            pii_action,
            jailbreak_detection_enabled: json.jailbreak_detection_enabled,
            schema_validation_enabled: json.schema_validation_enabled,
            max_tokens_per_request: json.max_tokens_per_request,
            add_cost_headers: json.add_cost_headers,
            allowed_models: json.allowed_models,
            block_mode: json.block_mode,
            fail_open: json.fail_open,
            rate_limit_requests: json.rate_limit_requests,
            rate_limit_tokens: json.rate_limit_tokens,
        }
    }
}

/// Configuration for the AI Gateway agent
#[derive(Debug, Clone)]
pub struct AiGatewayConfig {
    /// Enable prompt injection detection
    pub prompt_injection_enabled: bool,
    /// Enable PII detection
    pub pii_detection_enabled: bool,
    /// Action to take on PII detection
    pub pii_action: PiiAction,
    /// Enable jailbreak detection
    pub jailbreak_detection_enabled: bool,
    /// Enable JSON schema validation
    pub schema_validation_enabled: bool,
    /// Maximum tokens per request (None = no limit)
    pub max_tokens_per_request: Option<u32>,
    /// Add cost estimation headers
    pub add_cost_headers: bool,
    /// Allowed models (empty = allow all)
    pub allowed_models: Vec<String>,
    /// Block mode (false = detect-only, log but don't block)
    pub block_mode: bool,
    /// Fail open on errors
    pub fail_open: bool,
    /// Rate limit: requests per minute per client (0 = unlimited)
    pub rate_limit_requests: u32,
    /// Rate limit: tokens per minute per client (0 = unlimited)
    pub rate_limit_tokens: u32,
}

impl Default for AiGatewayConfig {
    fn default() -> Self {
        Self {
            prompt_injection_enabled: true,
            pii_detection_enabled: true,
            pii_action: PiiAction::Log,
            jailbreak_detection_enabled: true,
            schema_validation_enabled: false,
            max_tokens_per_request: None,
            add_cost_headers: true,
            allowed_models: Vec::new(),
            block_mode: true,
            fail_open: false,
            rate_limit_requests: 0,
            rate_limit_tokens: 0,
        }
    }
}

/// State for a single request being processed
#[derive(Default)]
struct RequestState {
    /// Detected AI provider
    provider: AiProvider,
    /// Accumulated body chunks
    body_chunks: Vec<Vec<u8>>,
    /// Client IP for rate limiting
    client_ip: String,
}

/// AI Gateway Agent
pub struct AiGatewayAgent {
    config: RwLock<AiGatewayConfig>,
    prompt_injection_detector: PromptInjectionDetector,
    pii_detector: PiiDetector,
    jailbreak_detector: JailbreakDetector,
    rate_limiter: RwLock<ratelimit::RateLimiter>,
    /// Per-request state, keyed by correlation ID
    requests: Arc<Mutex<HashMap<String, RequestState>>>,
}

impl AiGatewayAgent {
    /// Create a new AI Gateway agent with the given configuration
    pub fn new(config: AiGatewayConfig) -> Self {
        let rate_limit_config = ratelimit::RateLimitConfig {
            requests_per_minute: config.rate_limit_requests,
            tokens_per_minute: config.rate_limit_tokens,
            ..Default::default()
        };

        Self {
            prompt_injection_detector: PromptInjectionDetector::new(),
            pii_detector: PiiDetector::new(),
            jailbreak_detector: JailbreakDetector::new(),
            rate_limiter: RwLock::new(ratelimit::RateLimiter::new(rate_limit_config)),
            requests: Arc::new(Mutex::new(HashMap::new())),
            config: RwLock::new(config),
        }
    }

    /// Reconfigure the agent with new settings
    ///
    /// This allows dynamic reconfiguration without restarting the agent.
    pub async fn reconfigure(&self, config: AiGatewayConfig) {
        info!("Reconfiguring AI Gateway agent");

        // Update rate limiter with new config
        let rate_limit_config = ratelimit::RateLimitConfig {
            requests_per_minute: config.rate_limit_requests,
            tokens_per_minute: config.rate_limit_tokens,
            ..Default::default()
        };

        {
            let mut rate_limiter = self.rate_limiter.write().await;
            *rate_limiter = ratelimit::RateLimiter::new(rate_limit_config);
        }

        // Update config
        {
            let mut current_config = self.config.write().await;
            *current_config = config;
        }

        debug!("AI Gateway agent reconfigured successfully");
    }

    /// Process the complete request body
    async fn process_body(&self, state: &RequestState) -> AgentResponse {
        // Get config snapshot for this request
        let config = self.config.read().await.clone();

        // Combine body chunks
        let full_body: Vec<u8> = state.body_chunks.iter().flatten().copied().collect();
        let body_str = match String::from_utf8(full_body) {
            Ok(s) => s,
            Err(_) => {
                warn!("Invalid UTF-8 in request body");
                return if config.fail_open {
                    AgentResponse::default_allow().with_audit(AuditMetadata {
                        tags: vec!["ai-gateway".to_string(), "error".to_string()],
                        reason_codes: vec!["INVALID_UTF8".to_string()],
                        ..Default::default()
                    })
                } else {
                    AgentResponse::block(400, Some("Invalid request body".to_string())).with_audit(
                        AuditMetadata {
                            tags: vec!["ai-gateway".to_string(), "blocked".to_string()],
                            reason_codes: vec!["INVALID_UTF8".to_string()],
                            ..Default::default()
                        },
                    )
                };
            }
        };

        // Schema validation (before parsing)
        if config.schema_validation_enabled {
            let validation = providers::schema::validate_request(state.provider, &body_str);
            if !validation.valid {
                let errors_str = validation.errors.join("; ");
                warn!("Schema validation failed: {}", errors_str);

                if config.block_mode {
                    return AgentResponse::block(400, Some("Schema validation failed".to_string()))
                        .add_response_header(HeaderOp::Set {
                            name: "X-AI-Gateway-Schema-Valid".to_string(),
                            value: "false".to_string(),
                        })
                        .add_response_header(HeaderOp::Set {
                            name: "X-AI-Gateway-Schema-Errors".to_string(),
                            value: errors_str.clone(),
                        })
                        .with_audit(AuditMetadata {
                            tags: vec![
                                "ai-gateway".to_string(),
                                "blocked".to_string(),
                                "schema-invalid".to_string(),
                            ],
                            reason_codes: vec!["SCHEMA_VALIDATION_FAILED".to_string()],
                            ..Default::default()
                        });
                }
            }
        }

        // Parse the AI request
        let ai_request = match providers::parse_request(state.provider, &body_str) {
            Some(req) => req,
            None => {
                // Not a recognized AI request format - allow it through
                debug!("Not a recognized AI request format");
                return AgentResponse::default_allow().with_audit(AuditMetadata {
                    tags: vec!["ai-gateway".to_string()],
                    ..Default::default()
                });
            }
        };

        // Build response with checks
        self.check_request(&config, &ai_request, &state.provider, &body_str, &state.client_ip)
            .await
    }

    /// Run all security checks on the parsed AI request
    async fn check_request(
        &self,
        config: &AiGatewayConfig,
        request: &AiRequest,
        provider: &AiProvider,
        body: &str,
        client_ip: &str,
    ) -> AgentResponse {
        let mut response = AgentResponse::default_allow();
        let mut blocked = false;
        let mut block_reason = String::new();
        let mut tags = vec!["ai-gateway".to_string()];
        let mut reason_codes = Vec::new();

        // Add provider and model info headers
        response = response.add_request_header(HeaderOp::Set {
            name: "X-AI-Gateway-Provider".to_string(),
            value: provider.as_str().to_string(),
        });
        tags.push(format!("provider:{}", provider.as_str()));

        if let Some(ref model) = request.model {
            response = response.add_request_header(HeaderOp::Set {
                name: "X-AI-Gateway-Model".to_string(),
                value: model.clone(),
            });
            tags.push(format!("model:{}", model));
        }

        // Add schema validation header if enabled
        if config.schema_validation_enabled {
            let validation = providers::schema::validate_request(*provider, body);
            response = response.add_request_header(HeaderOp::Set {
                name: "X-AI-Gateway-Schema-Valid".to_string(),
                value: validation.valid.to_string(),
            });
            if validation.valid {
                tags.push("schema-valid".to_string());
            }
        }

        // Check model allowlist
        if !config.allowed_models.is_empty() {
            if let Some(ref model) = request.model {
                let model_allowed = config
                    .allowed_models
                    .iter()
                    .any(|allowed| model.contains(allowed) || allowed.contains(model));

                if !model_allowed {
                    blocked = true;
                    block_reason = "model-not-allowed".to_string();
                    reason_codes.push("MODEL_NOT_ALLOWED".to_string());
                    info!(model = model, "Model not in allowlist");
                }
            }
        }

        // Check token limits
        if let Some(max_tokens) = config.max_tokens_per_request {
            if let Some(requested_tokens) = request.max_tokens {
                if requested_tokens > max_tokens {
                    blocked = true;
                    block_reason = "token-limit-exceeded".to_string();
                    reason_codes.push("TOKEN_LIMIT_EXCEEDED".to_string());
                    info!(
                        requested = requested_tokens,
                        max = max_tokens,
                        "Token limit exceeded"
                    );
                }
            }
        }

        // Estimate tokens and add headers
        let estimated_tokens = request.estimate_tokens();
        response = response.add_request_header(HeaderOp::Set {
            name: "X-AI-Gateway-Tokens-Estimated".to_string(),
            value: estimated_tokens.to_string(),
        });

        // Add cost estimation if enabled
        if config.add_cost_headers {
            let cost = estimate_cost(provider, request.model.as_deref(), estimated_tokens);
            response = response.add_request_header(HeaderOp::Set {
                name: "X-AI-Gateway-Cost-Estimated".to_string(),
                value: format!("{:.6}", cost),
            });
        }

        // Rate limiting
        if config.rate_limit_requests > 0 || config.rate_limit_tokens > 0 {
            let rate_result = self
                .rate_limiter
                .read()
                .await
                .check_and_record(client_ip, estimated_tokens)
                .await;

            // Add rate limit headers
            if config.rate_limit_requests > 0 {
                response = response.add_response_header(HeaderOp::Set {
                    name: "X-RateLimit-Limit-Requests".to_string(),
                    value: rate_result.request_limit.to_string(),
                });
                response = response.add_response_header(HeaderOp::Set {
                    name: "X-RateLimit-Remaining-Requests".to_string(),
                    value: rate_result
                        .request_limit
                        .saturating_sub(rate_result.request_count)
                        .to_string(),
                });
            }
            if config.rate_limit_tokens > 0 {
                response = response.add_response_header(HeaderOp::Set {
                    name: "X-RateLimit-Limit-Tokens".to_string(),
                    value: rate_result.token_limit.to_string(),
                });
                response = response.add_response_header(HeaderOp::Set {
                    name: "X-RateLimit-Remaining-Tokens".to_string(),
                    value: rate_result
                        .token_limit
                        .saturating_sub(rate_result.token_count)
                        .to_string(),
                });
            }
            response = response.add_response_header(HeaderOp::Set {
                name: "X-RateLimit-Reset".to_string(),
                value: rate_result.reset_seconds.to_string(),
            });

            if !rate_result.allowed {
                let limit_type = match rate_result.exceeded_limit {
                    Some(ratelimit::ExceededLimit::Requests) => "requests",
                    Some(ratelimit::ExceededLimit::Tokens) => "tokens",
                    None => "unknown",
                };
                warn!(
                    client_ip = client_ip,
                    limit_type = limit_type,
                    "Rate limit exceeded"
                );
                tags.push("rate-limited".to_string());
                reason_codes.push("RATE_LIMIT_EXCEEDED".to_string());

                return AgentResponse::block(429, Some("Too Many Requests".to_string()))
                    .add_response_header(HeaderOp::Set {
                        name: "X-RateLimit-Limit-Requests".to_string(),
                        value: rate_result.request_limit.to_string(),
                    })
                    .add_response_header(HeaderOp::Set {
                        name: "X-RateLimit-Remaining-Requests".to_string(),
                        value: "0".to_string(),
                    })
                    .add_response_header(HeaderOp::Set {
                        name: "X-RateLimit-Reset".to_string(),
                        value: rate_result.reset_seconds.to_string(),
                    })
                    .add_response_header(HeaderOp::Set {
                        name: "Retry-After".to_string(),
                        value: rate_result.reset_seconds.to_string(),
                    })
                    .with_audit(AuditMetadata {
                        tags,
                        reason_codes,
                        ..Default::default()
                    });
            }
        }

        // Get all content for scanning
        let all_content = request.all_content();

        // Prompt injection detection
        if config.prompt_injection_enabled && !blocked {
            if let Some(detection) = self
                .prompt_injection_detector
                .detect_any(all_content.iter().copied())
            {
                warn!("Prompt injection detected: {}", detection);
                tags.push("detected:prompt-injection".to_string());
                reason_codes.push("PROMPT_INJECTION".to_string());
                if config.block_mode {
                    blocked = true;
                    block_reason = detection;
                }
            }
        }

        // Jailbreak detection
        if config.jailbreak_detection_enabled && !blocked {
            if let Some(detection) = self
                .jailbreak_detector
                .detect_any(all_content.iter().copied())
            {
                warn!("Jailbreak attempt detected: {}", detection);
                tags.push("detected:jailbreak".to_string());
                reason_codes.push("JAILBREAK_ATTEMPT".to_string());
                if config.block_mode {
                    blocked = true;
                    block_reason = detection;
                }
            }
        }

        // PII detection
        if config.pii_detection_enabled {
            let mut pii_types: Vec<PiiType> = Vec::new();
            for content in &all_content {
                pii_types.extend(self.pii_detector.detect_types(content));
            }
            pii_types.sort_by_key(|t| *t as u8);
            pii_types.dedup();

            if !pii_types.is_empty() {
                let pii_str = pii_types
                    .iter()
                    .map(|t| t.as_str())
                    .collect::<Vec<_>>()
                    .join(",");

                warn!("PII detected: {}", pii_str);
                response = response.add_request_header(HeaderOp::Set {
                    name: "X-AI-Gateway-PII-Detected".to_string(),
                    value: pii_str.clone(),
                });
                tags.push(format!("pii:{}", pii_str));
                reason_codes.push("PII_DETECTED".to_string());

                if config.pii_action == PiiAction::Block && config.block_mode {
                    blocked = true;
                    block_reason = format!("pii-detected:{}", pii_str);
                }
            }
        }

        // Apply blocking decision
        if blocked {
            tags.push("blocked".to_string());
            info!(reason = block_reason, "Request blocked");
            AgentResponse::block(403, Some("Forbidden".to_string()))
                .add_response_header(HeaderOp::Set {
                    name: "X-AI-Gateway-Blocked".to_string(),
                    value: "true".to_string(),
                })
                .add_response_header(HeaderOp::Set {
                    name: "X-AI-Gateway-Blocked-Reason".to_string(),
                    value: block_reason,
                })
                .with_audit(AuditMetadata {
                    tags,
                    reason_codes,
                    ..Default::default()
                })
        } else {
            response.with_audit(AuditMetadata {
                tags,
                reason_codes,
                ..Default::default()
            })
        }
    }
}

#[async_trait]
impl AgentHandler for AiGatewayAgent {
    async fn on_configure(&self, event: ConfigureEvent) -> AgentResponse {
        info!(agent_id = %event.agent_id, "Received configuration event");

        // Parse the JSON config
        let json_config: AiGatewayConfigJson = match serde_json::from_value(event.config) {
            Ok(cfg) => cfg,
            Err(e) => {
                warn!(error = %e, "Failed to parse configuration, using defaults");
                AiGatewayConfigJson::default()
            }
        };

        // Convert to internal config and apply
        let new_config: AiGatewayConfig = json_config.into();
        self.reconfigure(new_config).await;

        debug!("Configuration applied successfully");
        AgentResponse::default_allow()
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        let correlation_id = event.metadata.correlation_id.clone();
        let mut requests = self.requests.lock().await;

        // Detect provider from path and headers
        let provider = providers::detect_provider(&event.uri, &event.headers);

        debug!(
            correlation_id = %correlation_id,
            uri = %event.uri,
            provider = %provider.as_str(),
            "Request headers received"
        );

        // Store request state
        requests.insert(
            correlation_id,
            RequestState {
                provider,
                body_chunks: Vec::new(),
                client_ip: event.metadata.client_ip.clone(),
            },
        );

        AgentResponse::default_allow()
    }

    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        let mut requests = self.requests.lock().await;

        let state = match requests.get_mut(&event.correlation_id) {
            Some(s) => s,
            None => {
                // No state for this request, allow it
                return AgentResponse::default_allow();
            }
        };

        // Decode and accumulate body chunk
        if let Ok(decoded) = BASE64.decode(&event.data) {
            state.body_chunks.push(decoded);
        }

        // Process on last chunk
        if event.is_last {
            debug!(
                correlation_id = %event.correlation_id,
                chunks = state.body_chunks.len(),
                "Processing complete request body"
            );
            let state = requests.remove(&event.correlation_id).unwrap();
            // Drop the lock before async processing
            drop(requests);
            return self.process_body(&state).await;
        }

        AgentResponse::default_allow()
    }
}

/// Estimate cost based on provider, model, and token count
fn estimate_cost(provider: &AiProvider, model: Option<&str>, tokens: u32) -> f64 {
    // Rough cost per 1K tokens (input pricing, simplified)
    let cost_per_1k = match (provider, model) {
        (AiProvider::OpenAI, Some(m)) if m.contains("gpt-4o") => 0.005,
        (AiProvider::OpenAI, Some(m)) if m.contains("gpt-4-turbo") => 0.01,
        (AiProvider::OpenAI, Some(m)) if m.contains("gpt-4") => 0.03,
        (AiProvider::OpenAI, Some(m)) if m.contains("gpt-3.5") => 0.0005,
        (AiProvider::Anthropic, Some(m)) if m.contains("opus") => 0.015,
        (AiProvider::Anthropic, Some(m)) if m.contains("sonnet") => 0.003,
        (AiProvider::Anthropic, Some(m)) if m.contains("haiku") => 0.00025,
        (AiProvider::Azure, _) => 0.01, // Assume GPT-4 pricing
        _ => 0.01,                      // Default fallback
    };

    (tokens as f64 / 1000.0) * cost_per_1k
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AiGatewayConfig::default();
        assert!(config.prompt_injection_enabled);
        assert!(config.pii_detection_enabled);
        assert!(config.jailbreak_detection_enabled);
        assert!(config.block_mode);
        assert!(!config.fail_open);
    }

    #[test]
    fn test_pii_action_from_str() {
        assert_eq!("block".parse::<PiiAction>().unwrap(), PiiAction::Block);
        assert_eq!("redact".parse::<PiiAction>().unwrap(), PiiAction::Redact);
        assert_eq!("log".parse::<PiiAction>().unwrap(), PiiAction::Log);
        assert!("invalid".parse::<PiiAction>().is_err());
    }

    #[test]
    fn test_estimate_cost() {
        let tokens = 1000;

        // GPT-4
        let cost = estimate_cost(&AiProvider::OpenAI, Some("gpt-4"), tokens);
        assert!((cost - 0.03).abs() < 0.001);

        // Claude Opus
        let cost = estimate_cost(&AiProvider::Anthropic, Some("claude-3-opus"), tokens);
        assert!((cost - 0.015).abs() < 0.001);

        // GPT-3.5
        let cost = estimate_cost(&AiProvider::OpenAI, Some("gpt-3.5-turbo"), tokens);
        assert!((cost - 0.0005).abs() < 0.0001);
    }
}
