# Sentinel AI Gateway Agent

An AI gateway agent for [Sentinel](https://sentinel.raskell.io) reverse proxy that provides comprehensive security and control for AI API requests (OpenAI, Anthropic, Azure OpenAI).

## Features

### Security Controls

- **Prompt Injection Detection**: Blocks attempts to override system prompts or manipulate AI behavior
- **Jailbreak Detection**: Detects attempts to bypass AI safety measures (DAN, developer mode, etc.)
- **PII Detection**: Detects personally identifiable information (email, SSN, phone, credit card)
  - Configurable actions: block, log, or redact (coming soon)

### Usage Control

- **Token Limits**: Enforce maximum tokens per request
- **Cost Estimation**: Add headers with estimated cost based on model pricing
- **Model Allowlist**: Restrict which AI models can be used

### Observability

- **Provider Detection**: Automatically detect AI provider (OpenAI, Anthropic, Azure)
- **Audit Tags**: Add tags for logging and monitoring
- **Request Headers**: Add informational headers for downstream processing

## Installation

```bash
cargo install sentinel-agent-ai-gateway
```

Or build from source:

```bash
git clone https://github.com/raskell-io/sentinel-agent-ai-gateway
cd sentinel-agent-ai-gateway
cargo build --release
```

## Usage

### Basic Usage

```bash
sentinel-ai-gateway-agent --socket /tmp/sentinel-ai.sock
```

### With Options

```bash
sentinel-ai-gateway-agent \
  --socket /tmp/sentinel-ai.sock \
  --allowed-models "gpt-4,gpt-3.5-turbo,claude-3" \
  --max-tokens 4000 \
  --pii-action block \
  --block-mode
```

### Environment Variables

All CLI options can be configured via environment variables:

| Option | Env Var | Description | Default |
|--------|---------|-------------|---------|
| `--socket` | `AGENT_SOCKET` | Unix socket path | `/tmp/sentinel-ai-gateway.sock` |
| `--prompt-injection` | `PROMPT_INJECTION` | Enable prompt injection detection | `true` |
| `--pii-detection` | `PII_DETECTION` | Enable PII detection | `true` |
| `--pii-action` | `PII_ACTION` | Action on PII: block/redact/log | `log` |
| `--jailbreak-detection` | `JAILBREAK_DETECTION` | Enable jailbreak detection | `true` |
| `--allowed-models` | `ALLOWED_MODELS` | Comma-separated model allowlist | (all) |
| `--max-tokens` | `MAX_TOKENS` | Max tokens per request (0 = no limit) | `0` |
| `--add-cost-headers` | `ADD_COST_HEADERS` | Add cost estimation headers | `true` |
| `--block-mode` | `BLOCK_MODE` | Block or detect-only | `true` |
| `--fail-open` | `FAIL_OPEN` | Allow on errors | `false` |
| `--verbose` | `VERBOSE` | Enable debug logging | `false` |

## Sentinel Configuration

Configure Sentinel proxy to use this agent:

```yaml
agents:
  - name: ai-gateway
    type: socket
    socket_path: /tmp/sentinel-ai-gateway.sock
    timeout: 5s
    events:
      - request_headers
      - request_body_chunk

routes:
  - match:
      hosts: ["api.openai.com", "api.anthropic.com"]
    agents:
      - ai-gateway
    upstream: ai-backend
```

## Headers Added

The agent adds the following headers to requests:

| Header | Description |
|--------|-------------|
| `X-AI-Gateway-Provider` | Detected provider (openai, anthropic, azure) |
| `X-AI-Gateway-Model` | Model from request |
| `X-AI-Gateway-Tokens-Estimated` | Estimated token count |
| `X-AI-Gateway-Cost-Estimated` | Estimated cost in USD |
| `X-AI-Gateway-PII-Detected` | Comma-separated PII types found |
| `X-AI-Gateway-Blocked` | `true` if request was blocked |
| `X-AI-Gateway-Blocked-Reason` | Reason for blocking |

## Detection Patterns

### Prompt Injection

Detects patterns like:
- "Ignore previous instructions"
- "You are now a..."
- "System prompt:"
- Role manipulation attempts
- System prompt extraction attempts

### Jailbreak

Detects patterns like:
- DAN (Do Anything Now) and variants
- Developer/debug mode requests
- Bypass attempts
- Hypothetical framing ("for educational purposes")
- Evil/uncensored mode requests

### PII

Detects:
- Email addresses
- Social Security Numbers (SSN)
- Phone numbers (US format)
- Credit card numbers
- Public IP addresses

## Supported AI Providers

| Provider | Detection | Paths |
|----------|-----------|-------|
| OpenAI | `Bearer sk-*` header | `/v1/chat/completions`, `/v1/completions` |
| Anthropic | `anthropic-version` header | `/v1/messages`, `/v1/complete` |
| Azure OpenAI | Path pattern | `/openai/deployments/*/chat/completions` |

## API

### As a Library

```rust
use sentinel_agent_ai_gateway::{AiGatewayAgent, AiGatewayConfig, PiiAction};
use sentinel_agent_protocol::AgentServer;

let config = AiGatewayConfig {
    prompt_injection_enabled: true,
    pii_detection_enabled: true,
    pii_action: PiiAction::Block,
    jailbreak_detection_enabled: true,
    max_tokens_per_request: Some(4000),
    allowed_models: vec!["gpt-4".to_string()],
    block_mode: true,
    fail_open: false,
    ..Default::default()
};

let agent = AiGatewayAgent::new(config);
let server = AgentServer::new("ai-gateway", "/tmp/ai.sock", Box::new(agent));
server.run().await?;
```

## Testing

```bash
# Run all tests
cargo test

# Run with verbose output
cargo test -- --nocapture
```

## Related Agents

- [sentinel-agent-waf](https://github.com/raskell-io/sentinel-agent-waf) - Web Application Firewall
- [sentinel-agent-modsec](https://github.com/raskell-io/sentinel-agent-modsec) - ModSecurity with OWASP CRS
- [sentinel-agent-js](https://github.com/raskell-io/sentinel-agent-js) - JavaScript scripting
- [sentinel-agent-wasm](https://github.com/raskell-io/sentinel-agent-wasm) - WebAssembly plugins

## License

MIT OR Apache-2.0
