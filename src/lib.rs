//! AI Gateway Agent for Zentinel proxy.
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
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};
use zentinel_agent_protocol::v2::{
    AgentCapabilities, AgentFeatures, AgentHandlerV2, CounterMetric, DrainReason, GaugeMetric,
    HealthStatus, MetricsReport, ShutdownReason,
};
use zentinel_agent_protocol::{
    AgentResponse, AuditMetadata, EventType, HeaderOp, RequestBodyChunkEvent, RequestHeadersEvent,
};

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

/// The agent's `config { }` block, as the proxy delivers it in Configure.
///
/// Every field is optional: the block overlays the settings the agent was
/// started with (flags and environment), and a field the block leaves out
/// keeps that value. Keys are kebab-case, as written in KDL. An unknown key is
/// an error, so a typo cannot silently fall back to a default.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AiGatewayConfigJson {
    /// Enable prompt injection detection
    pub prompt_injection_enabled: Option<bool>,
    /// Enable PII detection
    pub pii_detection_enabled: Option<bool>,
    /// Action to take on PII detection: "block", "redact", or "log"
    pub pii_action: Option<String>,
    /// Enable jailbreak detection
    pub jailbreak_detection_enabled: Option<bool>,
    /// Enable JSON schema validation
    pub schema_validation_enabled: Option<bool>,
    /// Maximum tokens per request (0 = no limit)
    pub max_tokens_per_request: Option<u32>,
    /// Add cost estimation headers
    pub add_cost_headers: Option<bool>,
    /// Allowed models: one string (comma-separated) or a list of strings
    pub allowed_models: Option<StringOrList>,
    /// Block mode (false = detect-only, log but don't block)
    pub block_mode: Option<bool>,
    /// Fail open on errors
    pub fail_open: Option<bool>,
    /// Rate limit: requests per minute per client (0 = unlimited)
    pub rate_limit_requests: Option<u32>,
    /// Rate limit: tokens per minute per client (0 = unlimited)
    pub rate_limit_tokens: Option<u32>,
}

/// A KDL node with one argument arrives as a scalar, with several as a list.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum StringOrList {
    One(String),
    Many(Vec<String>),
}

impl StringOrList {
    /// The entries, split on commas and trimmed, without empty ones.
    ///
    /// An input that names something but leaves nothing (`""`, `","`) is an
    /// error: an allowlist that silently became empty would allow every model.
    fn entries(&self, key: &str) -> Result<Vec<String>, String> {
        let raw: Vec<&str> = match self {
            StringOrList::One(s) => vec![s.as_str()],
            StringOrList::Many(v) => v.iter().map(String::as_str).collect(),
        };
        let entries: Vec<String> = raw
            .iter()
            .flat_map(|s| s.split(','))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if entries.is_empty() && !raw.is_empty() {
            return Err(format!("`{key}` has no usable entries"));
        }
        Ok(entries)
    }
}

impl AiGatewayConfigJson {
    /// Parse a Configure payload, rejecting unknown keys and wrong types.
    pub fn parse(value: serde_json::Value) -> Result<Self, String> {
        serde_json::from_value(value).map_err(|e| e.to_string())
    }

    /// The effective configuration: `base` with every field this block sets.
    pub fn apply_to(&self, base: &AiGatewayConfig) -> Result<AiGatewayConfig, String> {
        let mut config = base.clone();
        if let Some(v) = self.prompt_injection_enabled {
            config.prompt_injection_enabled = v;
        }
        if let Some(v) = self.pii_detection_enabled {
            config.pii_detection_enabled = v;
        }
        if let Some(ref v) = self.pii_action {
            config.pii_action = v.parse::<PiiAction>()?;
        }
        if let Some(v) = self.jailbreak_detection_enabled {
            config.jailbreak_detection_enabled = v;
        }
        if let Some(v) = self.schema_validation_enabled {
            config.schema_validation_enabled = v;
        }
        if let Some(v) = self.max_tokens_per_request {
            config.max_tokens_per_request = if v == 0 { None } else { Some(v) };
        }
        if let Some(v) = self.add_cost_headers {
            config.add_cost_headers = v;
        }
        if let Some(ref v) = self.allowed_models {
            config.allowed_models = v.entries("allowed-models")?;
        }
        if let Some(v) = self.block_mode {
            config.block_mode = v;
        }
        if let Some(v) = self.fail_open {
            config.fail_open = v;
        }
        if let Some(v) = self.rate_limit_requests {
            config.rate_limit_requests = v;
        }
        if let Some(v) = self.rate_limit_tokens {
            config.rate_limit_tokens = v;
        }
        Ok(config)
    }
}

/// A stable hash of a JSON value with its object keys in sorted order, so two
/// payloads that differ only in key order hash the same (FNV-1a, 64 bit).
pub fn canonical_config_hash(value: &serde_json::Value) -> u64 {
    fn write(value: &serde_json::Value, out: &mut String) {
        match value {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                out.push('{');
                for (i, k) in keys.into_iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::Value::String(k.clone()).to_string());
                    out.push(':');
                    write(&map[k], out);
                }
                out.push('}');
            }
            serde_json::Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(item, out);
                }
                out.push(']');
            }
            other => out.push_str(&other.to_string()),
        }
    }
    let mut canonical = String::new();
    write(value, &mut canonical);
    canonical.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

impl AiGatewayConfig {
    /// The names (as config keys) of the settings that differ from `other`.
    pub fn changed_keys(&self, other: &AiGatewayConfig) -> Vec<&'static str> {
        let mut keys = Vec::new();
        macro_rules! cmp {
            ($field:ident, $key:literal) => {
                if self.$field != other.$field {
                    keys.push($key);
                }
            };
        }
        cmp!(prompt_injection_enabled, "prompt-injection-enabled");
        cmp!(pii_detection_enabled, "pii-detection-enabled");
        cmp!(pii_action, "pii-action");
        cmp!(jailbreak_detection_enabled, "jailbreak-detection-enabled");
        cmp!(schema_validation_enabled, "schema-validation-enabled");
        cmp!(max_tokens_per_request, "max-tokens-per-request");
        cmp!(add_cost_headers, "add-cost-headers");
        cmp!(allowed_models, "allowed-models");
        cmp!(block_mode, "block-mode");
        cmp!(fail_open, "fail-open");
        cmp!(rate_limit_requests, "rate-limit-requests");
        cmp!(rate_limit_tokens, "rate-limit-tokens");
        keys
    }
}

/// Configuration for the AI Gateway agent
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// The settings the agent was started with; a `config { }` block overlays these.
    base_config: AiGatewayConfig,
    /// Hash of the last Configure payload that was applied. Held for the whole
    /// of `on_configure`, which also serialises concurrent configures.
    applied_config_hash: Mutex<Option<u64>>,
    /// Per-request state, keyed by correlation ID
    requests: Arc<Mutex<HashMap<String, RequestState>>>,
    /// Metrics: total requests processed
    requests_total: AtomicU64,
    /// Metrics: requests blocked
    requests_blocked: AtomicU64,
    /// Metrics: prompt injection detections
    prompt_injection_detections: AtomicU64,
    /// Metrics: PII detections
    pii_detections: AtomicU64,
    /// Metrics: jailbreak detections
    jailbreak_detections: AtomicU64,
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
            base_config: config.clone(),
            applied_config_hash: Mutex::new(None),
            config: RwLock::new(config),
            requests_total: AtomicU64::new(0),
            requests_blocked: AtomicU64::new(0),
            prompt_injection_detections: AtomicU64::new(0),
            pii_detections: AtomicU64::new(0),
            jailbreak_detections: AtomicU64::new(0),
        }
    }

    /// Reconfigure the agent with new settings
    ///
    /// This allows dynamic reconfiguration without restarting the agent.
    /// Rate-limit usage is kept: only the limits change, so clients keep the
    /// counts they have used in the current window.
    pub async fn reconfigure(&self, config: AiGatewayConfig) {
        let rate_limit_config = ratelimit::RateLimitConfig {
            requests_per_minute: config.rate_limit_requests,
            tokens_per_minute: config.rate_limit_tokens,
            ..Default::default()
        };

        {
            let mut rate_limiter = self.rate_limiter.write().await;
            if *rate_limiter.config() != rate_limit_config {
                rate_limiter.set_config(rate_limit_config);
            }
        }

        *self.config.write().await = config;
    }

    /// Apply a Configure payload: overlay it on the startup settings.
    ///
    /// Returns the hash of the payload and the keys whose effective value
    /// changed, or an error for an unknown key or invalid value (nothing is
    /// applied then). A payload identical to the one last applied is a no-op.
    pub async fn apply_configure(
        &self,
        config: serde_json::Value,
    ) -> Result<(u64, Vec<&'static str>), String> {
        let hash = canonical_config_hash(&config);
        let mut applied = self.applied_config_hash.lock().await;
        if *applied == Some(hash) {
            return Ok((hash, Vec::new()));
        }

        let new_config = AiGatewayConfigJson::parse(config)?.apply_to(&self.base_config)?;
        let changed = self.config.read().await.changed_keys(&new_config);
        if !changed.is_empty() {
            self.reconfigure(new_config).await;
        }
        *applied = Some(hash);
        Ok((hash, changed))
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
        self.check_request(
            &config,
            &ai_request,
            &state.provider,
            &body_str,
            &state.client_ip,
        )
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
                self.prompt_injection_detections
                    .fetch_add(1, Ordering::Relaxed);
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
                self.jailbreak_detections.fetch_add(1, Ordering::Relaxed);
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
                self.pii_detections.fetch_add(1, Ordering::Relaxed);
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
impl AgentHandlerV2 for AiGatewayAgent {
    /// Get agent capabilities for v2 protocol handshake.
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("ai-gateway", "AI Gateway Agent", env!("CARGO_PKG_VERSION"))
            .with_event(EventType::RequestHeaders)
            .with_event(EventType::RequestBodyChunk)
            .with_features(AgentFeatures {
                streaming_body: true,
                config_push: true,
                health_reporting: true,
                metrics_export: true,
                concurrent_requests: 100,
                cancellation: true,
                ..Default::default()
            })
    }

    /// Handle configuration updates from the proxy.
    ///
    /// The proxy sends the `config { }` block on every connection, so this
    /// runs once per pooled connection and again on every reconnect. It must
    /// be idempotent; see `apply_configure`. The payload is never logged
    /// (it is the operator's config), only its hash and the changed keys.
    async fn on_configure(&self, config: serde_json::Value, version: Option<String>) -> bool {
        match self.apply_configure(config).await {
            Ok((hash, changed)) if changed.is_empty() => {
                debug!(version = ?version, config_hash = %format!("{hash:016x}"), "Configuration unchanged");
                true
            }
            Ok((hash, changed)) => {
                info!(version = ?version, config_hash = %format!("{hash:016x}"), changed = ?changed, "Configuration applied");
                true
            }
            Err(e) => {
                warn!(version = ?version, error = %e, "Rejected configuration; keeping the current settings");
                false
            }
        }
    }

    /// Get current health status for v2 protocol.
    fn health_status(&self) -> HealthStatus {
        HealthStatus::healthy("ai-gateway")
    }

    /// Get current metrics report for v2 protocol.
    fn metrics_report(&self) -> Option<MetricsReport> {
        let mut report = MetricsReport::new("ai-gateway", 10_000);

        report.counters.push(CounterMetric::new(
            "ai_gateway_requests_total",
            self.requests_total.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "ai_gateway_requests_blocked_total",
            self.requests_blocked.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "ai_gateway_prompt_injection_detections_total",
            self.prompt_injection_detections.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "ai_gateway_pii_detections_total",
            self.pii_detections.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "ai_gateway_jailbreak_detections_total",
            self.jailbreak_detections.load(Ordering::Relaxed),
        ));

        // Add gauge for in-flight requests
        let in_flight = self.requests.try_lock().map(|r| r.len()).unwrap_or(0);
        report.gauges.push(GaugeMetric::new(
            "ai_gateway_in_flight_requests",
            in_flight as f64,
        ));

        Some(report)
    }

    /// Handle shutdown request from proxy.
    async fn on_shutdown(&self, reason: ShutdownReason, grace_period_ms: u64) {
        info!(
            reason = ?reason,
            grace_period_ms = grace_period_ms,
            "Received shutdown request"
        );
        // Clean up any pending requests
        let mut requests = self.requests.lock().await;
        requests.clear();
    }

    /// Handle drain request from proxy.
    async fn on_drain(&self, duration_ms: u64, reason: DrainReason) {
        info!(
            duration_ms = duration_ms,
            reason = ?reason,
            "Received drain request"
        );
        // In drain mode, we continue processing existing requests but stop accepting new ones
        // The proxy handles this by not sending new requests
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

            // Track metrics
            self.requests_total.fetch_add(1, Ordering::Relaxed);

            let response = self.process_body(&state).await;

            // Track blocked requests
            if matches!(
                response.decision,
                zentinel_agent_protocol::Decision::Block { .. }
            ) {
                self.requests_blocked.fetch_add(1, Ordering::Relaxed);
            }

            return response;
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

    /// Settings as if started with non-default flags.
    fn cli_config() -> AiGatewayConfig {
        AiGatewayConfig {
            pii_action: PiiAction::Block,
            schema_validation_enabled: true,
            max_tokens_per_request: Some(4096),
            allowed_models: vec!["gpt-4".to_string()],
            block_mode: false,
            fail_open: true,
            rate_limit_requests: 3,
            rate_limit_tokens: 0,
            ..AiGatewayConfig::default()
        }
    }

    async fn use_quota(agent: &AiGatewayAgent, client: &str, n: u32) {
        for _ in 0..n {
            let r = agent
                .rate_limiter
                .read()
                .await
                .check_and_record(client, 0)
                .await;
            assert!(r.allowed);
        }
    }

    async fn usage(agent: &AiGatewayAgent, client: &str) -> Option<(u32, u32)> {
        agent.rate_limiter.read().await.get_state(client).await
    }

    #[tokio::test]
    async fn identical_configure_twice_keeps_rate_limit_usage() {
        let agent = AiGatewayAgent::new(cli_config());
        let block = serde_json::json!({ "rate-limit-requests": 3, "pii-action": "log" });

        assert!(agent.on_configure(block.clone(), None).await);
        use_quota(&agent, "10.0.0.1", 2).await;

        // A second connection (or a reconnect) delivers the same block.
        assert!(agent.on_configure(block.clone(), None).await);
        assert!(agent.on_configure(block, None).await);

        assert_eq!(usage(&agent, "10.0.0.1").await, Some((2, 0)));
        use_quota(&agent, "10.0.0.1", 1).await;
        let r = agent
            .rate_limiter
            .read()
            .await
            .check_and_record("10.0.0.1", 0)
            .await;
        assert!(!r.allowed, "the client is at its limit");
    }

    #[tokio::test]
    async fn changed_configure_keeps_usage_and_applies_new_limit() {
        let agent = AiGatewayAgent::new(cli_config());
        use_quota(&agent, "10.0.0.1", 2).await;

        assert!(
            agent
                .on_configure(serde_json::json!({ "rate-limit-requests": 5 }), None)
                .await
        );
        assert_eq!(usage(&agent, "10.0.0.1").await, Some((2, 0)));
        assert_eq!(
            agent.rate_limiter.read().await.config().requests_per_minute,
            5
        );
        assert_eq!(agent.config.read().await.rate_limit_requests, 5);

        // A change to an unrelated setting leaves usage alone as well.
        assert!(
            agent
                .on_configure(serde_json::json!({ "block-mode": true }), None)
                .await
        );
        assert_eq!(usage(&agent, "10.0.0.1").await, Some((2, 0)));
    }

    #[tokio::test]
    async fn partial_configure_keeps_cli_values() {
        let agent = AiGatewayAgent::new(cli_config());
        assert!(
            agent
                .on_configure(
                    serde_json::json!({ "jailbreak-detection-enabled": false }),
                    None
                )
                .await
        );

        let expected = AiGatewayConfig {
            jailbreak_detection_enabled: false,
            ..cli_config()
        };
        assert_eq!(*agent.config.read().await, expected);
    }

    #[tokio::test]
    async fn empty_configure_keeps_cli_values() {
        let agent = AiGatewayAgent::new(cli_config());
        assert!(agent.on_configure(serde_json::json!({}), None).await);
        assert_eq!(*agent.config.read().await, cli_config());
    }

    #[tokio::test]
    async fn unknown_key_is_rejected_and_nothing_changes() {
        let agent = AiGatewayAgent::new(cli_config());
        use_quota(&agent, "10.0.0.1", 2).await;

        // `rate-limit-request` is a typo for `rate-limit-requests`.
        let typo = serde_json::json!({ "rate-limit-request": 100, "block-mode": true });
        assert!(!agent.on_configure(typo.clone(), None).await);
        // Rejected again, not remembered as applied.
        assert!(!agent.on_configure(typo, None).await);

        assert_eq!(*agent.config.read().await, cli_config());
        assert_eq!(usage(&agent, "10.0.0.1").await, Some((2, 0)));
    }

    #[tokio::test]
    async fn invalid_values_are_rejected() {
        let agent = AiGatewayAgent::new(cli_config());
        for bad in [
            serde_json::json!({ "pii-action": "blok" }),
            serde_json::json!({ "allowed-models": "" }),
            serde_json::json!({ "allowed-models": [",", " "] }),
            serde_json::json!({ "rate-limit-requests": "lots" }),
            serde_json::json!({ "allowed-models": true }),
        ] {
            assert!(!agent.on_configure(bad.clone(), None).await, "{bad}");
        }
        assert_eq!(*agent.config.read().await, cli_config());
    }

    #[tokio::test]
    async fn allowed_models_accepts_scalar_and_list() {
        let agent = AiGatewayAgent::new(cli_config());
        // One KDL argument arrives as a string.
        assert!(
            agent
                .on_configure(serde_json::json!({ "allowed-models": "claude-3" }), None)
                .await
        );
        assert_eq!(agent.config.read().await.allowed_models, vec!["claude-3"]);
        // Several arrive as a list.
        assert!(
            agent
                .on_configure(serde_json::json!({ "allowed-models": ["a", "b"] }), None)
                .await
        );
        assert_eq!(agent.config.read().await.allowed_models, vec!["a", "b"]);
    }

    #[test]
    fn config_hash_ignores_key_order() {
        let a: serde_json::Value =
            serde_json::from_str(r#"{"a":1,"b":{"x":true,"y":[1,2]}}"#).unwrap();
        let b: serde_json::Value =
            serde_json::from_str(r#"{"b":{"y":[1,2],"x":true},"a":1}"#).unwrap();
        let c: serde_json::Value =
            serde_json::from_str(r#"{"a":1,"b":{"x":true,"y":[2,1]}}"#).unwrap();
        assert_eq!(canonical_config_hash(&a), canonical_config_hash(&b));
        assert_ne!(canonical_config_hash(&a), canonical_config_hash(&c));
    }
}
