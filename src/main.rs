//! AI Gateway Agent CLI for Sentinel proxy.

use anyhow::Result;
use clap::Parser;
use sentinel_agent_ai_gateway::{AiGatewayAgent, AiGatewayConfig, PiiAction};
use sentinel_agent_protocol::v2::GrpcAgentServerV2;
use sentinel_agent_protocol::AgentServer;
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

/// AI Gateway Agent for Sentinel proxy
///
/// Provides security controls for AI API requests including prompt injection
/// detection, PII filtering, jailbreak detection, and usage controls.
#[derive(Parser, Debug)]
#[command(name = "sentinel-agent-ai-gateway")]
#[command(version, about, long_about = None)]
struct Args {
    /// Unix socket path for agent communication (UDS transport)
    #[arg(
        long,
        env = "AGENT_SOCKET",
        default_value = "/tmp/sentinel-ai-gateway.sock"
    )]
    socket: String,

    /// gRPC address for agent communication (e.g., 0.0.0.0:50051)
    /// When specified, the agent will use gRPC transport instead of UDS
    #[arg(long, env = "GRPC_ADDRESS")]
    grpc_address: Option<String>,

    /// Enable prompt injection detection
    #[arg(long, env = "PROMPT_INJECTION", default_value = "true")]
    prompt_injection: bool,

    /// Enable PII detection
    #[arg(long, env = "PII_DETECTION", default_value = "true")]
    pii_detection: bool,

    /// Action on PII detection: block, redact, log
    #[arg(long, env = "PII_ACTION", default_value = "log")]
    pii_action: String,

    /// Enable jailbreak detection
    #[arg(long, env = "JAILBREAK_DETECTION", default_value = "true")]
    jailbreak_detection: bool,

    /// Enable JSON schema validation
    #[arg(long, env = "SCHEMA_VALIDATION", default_value = "false")]
    schema_validation: bool,

    /// Comma-separated list of allowed models (empty = allow all)
    #[arg(long, env = "ALLOWED_MODELS", default_value = "")]
    allowed_models: String,

    /// Maximum tokens per request (0 = no limit)
    #[arg(long, env = "MAX_TOKENS", default_value = "0")]
    max_tokens: u32,

    /// Add cost estimation headers
    #[arg(long, env = "ADD_COST_HEADERS", default_value = "true")]
    add_cost_headers: bool,

    /// Block mode (false = detect-only, log but don't block)
    #[arg(long, env = "BLOCK_MODE", default_value = "true")]
    block_mode: bool,

    /// Allow requests on processing errors
    #[arg(long, env = "FAIL_OPEN", default_value = "false")]
    fail_open: bool,

    /// Rate limit: requests per minute per client (0 = unlimited)
    #[arg(long, env = "RATE_LIMIT_REQUESTS", default_value = "0")]
    rate_limit_requests: u32,

    /// Rate limit: tokens per minute per client (0 = unlimited)
    #[arg(long, env = "RATE_LIMIT_TOKENS", default_value = "0")]
    rate_limit_tokens: u32,

    /// Enable verbose debug logging
    #[arg(long, short, env = "VERBOSE", default_value = "false")]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let filter = if args.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };

    fmt().with_env_filter(filter).with_target(false).init();

    // Parse PII action
    let pii_action: PiiAction = args.pii_action.parse().unwrap_or_else(|e| {
        eprintln!("Warning: {}, defaulting to 'log'", e);
        PiiAction::Log
    });

    // Parse allowed models
    let allowed_models: Vec<String> = if args.allowed_models.is_empty() {
        Vec::new()
    } else {
        args.allowed_models
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };

    // Build config
    let config = AiGatewayConfig {
        prompt_injection_enabled: args.prompt_injection,
        pii_detection_enabled: args.pii_detection,
        pii_action,
        jailbreak_detection_enabled: args.jailbreak_detection,
        schema_validation_enabled: args.schema_validation,
        max_tokens_per_request: if args.max_tokens == 0 {
            None
        } else {
            Some(args.max_tokens)
        },
        add_cost_headers: args.add_cost_headers,
        allowed_models,
        block_mode: args.block_mode,
        fail_open: args.fail_open,
        rate_limit_requests: args.rate_limit_requests,
        rate_limit_tokens: args.rate_limit_tokens,
    };

    info!("Starting AI Gateway Agent");
    info!("  Socket: {}", args.socket);
    info!(
        "  Prompt injection detection: {}",
        config.prompt_injection_enabled
    );
    info!("  PII detection: {}", config.pii_detection_enabled);
    info!("  PII action: {:?}", config.pii_action);
    info!(
        "  Jailbreak detection: {}",
        config.jailbreak_detection_enabled
    );
    info!("  Schema validation: {}", config.schema_validation_enabled);
    info!("  Max tokens: {:?}", config.max_tokens_per_request);
    info!("  Block mode: {}", config.block_mode);
    info!("  Fail open: {}", config.fail_open);

    if config.rate_limit_requests > 0 || config.rate_limit_tokens > 0 {
        info!(
            "  Rate limit: {} req/min, {} tokens/min",
            config.rate_limit_requests, config.rate_limit_tokens
        );
    }

    if !config.allowed_models.is_empty() {
        info!("  Allowed models: {:?}", config.allowed_models);
    }

    let agent = AiGatewayAgent::new(config);

    // Choose transport based on CLI arguments
    if let Some(grpc_addr) = args.grpc_address {
        // Use gRPC transport (v2 protocol)
        info!("Starting AI Gateway Agent with gRPC transport on {}", grpc_addr);
        let addr: std::net::SocketAddr = grpc_addr
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid gRPC address '{}': {}", grpc_addr, e))?;
        let server = GrpcAgentServerV2::new("ai-gateway", Box::new(agent));
        server.run(addr).await?;
    } else {
        // Use UDS transport (v1 protocol for backward compatibility)
        info!("Starting AI Gateway Agent with UDS transport on {}", args.socket);
        let server = AgentServer::new("ai-gateway", &args.socket, Box::new(agent));
        server.run().await?;
    }

    Ok(())
}
