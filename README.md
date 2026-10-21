<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">AI gateway agent</h3>

<p align="center">Pattern-based checks on OpenAI, Azure OpenAI and Anthropic API requests: prompt injection, jailbreaks, PII, model allowlist, token and rate limits, run on the request body.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-agent-ai-gateway/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-agent-ai-gateway/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-9b4d8a?style=flat&amp;labelColor=1f161e">
  <img alt="Rust 1.94.1+" src="https://img.shields.io/badge/rust-1.94.1%2B-f68d31?style=flat&amp;labelColor=1f161e&amp;logo=rust&amp;logoColor=white">
  <img alt="Agent protocol v2" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&amp;labelColor=1f161e">
</p>

<p align="center">
  <a href="https://registry.zentinelproxy.io/ai-gateway/">Registry</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

For teams that put an LLM API behind Zentinel and want a first, cheap filter in
front of it. The agent detects the provider from the request path, parses the
JSON body once it has all of it, and checks the messages and system prompt
against fixed regular expressions, the model against an allowlist and the
requested `max_tokens` against a limit. A failed check blocks with 403 (429 for
rate limits, 400 for schema errors); with `--block-mode` off, detections are
only logged and tagged. If the agent cannot be reached, the filter's
`failure-mode` decides; the quick start uses `closed`.

The detectors are regular expressions, not a model. They catch the well-known
phrasings and miss paraphrases, and some patterns over-match (see
[How it works](#how-it-works)). Start in detect-only mode and read the logs
before you block.

## Quick start

```bash
cargo install --git https://github.com/zentinelproxy/zentinel-agent-ai-gateway
zentinel-ai-gateway-agent --socket /tmp/zentinel-ai-gateway.sock
```

```kdl
system {
    worker-threads 0
}

listeners {
    listener "http" {
        address "0.0.0.0:8080"
        protocol "http"
    }
}

upstreams {
    upstream "llm" {
        target "127.0.0.1:3000"
    }
}

agents {
    agent "ai-gateway" type="custom" {
        unix-socket "/tmp/zentinel-ai-gateway.sock"
        events "request_headers" "request_body"
        request-body-mode "buffer"
        max-request-body-bytes 1048576
        timeout-ms 500
    }
}

filters {
    filter "ai-gateway" {
        type "agent"
        agent "ai-gateway"
        failure-mode "closed"
    }
}

routes {
    route "llm" {
        matches { path-prefix "/v1/" }
        upstream "llm"
        filters "ai-gateway"
    }
}
```

The agent decides on the request body, so `request_body` must be in `events`;
with `request_headers` alone it allows everything.

## Install

Not in the Zentinel bundle yet: `zentinel bundle install ai-gateway` fails
because the repository has no releases.

### From source (recommended)

```bash
cargo install --git https://github.com/zentinelproxy/zentinel-agent-ai-gateway
```

Installs the `zentinel-ai-gateway-agent` binary. Needs Rust 1.94.1 or newer and
`protoc`. Or clone and build:

```bash
git clone https://github.com/zentinelproxy/zentinel-agent-ai-gateway
cd zentinel-agent-ai-gateway
cargo build --release   # target/release/zentinel-ai-gateway-agent
```

### Container image (build locally)

No image is published. The `Dockerfile` packages a binary you built first:

```bash
cargo build --release
cp target/release/zentinel-ai-gateway-agent .
docker build --target prebuilt -t zentinel-ai-gateway-agent .
```

The image sets `SOCKET_PATH`, which the agent does not read; pass `--socket`
or `AGENT_SOCKET`.

## Configuration

Every option is a flag with an environment variable. The agent also accepts
configuration over the protocol (`on_configure`), but Zentinel 0.6.50 does not
forward an `agent { config { ... } }` block, so set it here.

| Option | Default | Meaning |
|---|---|---|
| `--socket` | `/tmp/zentinel-ai-gateway.sock` | Unix socket to listen on. Env `AGENT_SOCKET`. |
| `--grpc-address` | unset | Listen on gRPC at this address (e.g. `0.0.0.0:50051`) instead of the socket. Env `GRPC_ADDRESS`. |
| `--prompt-injection` | `true` | Prompt injection detection. Env `PROMPT_INJECTION`. |
| `--jailbreak-detection` | `true` | Jailbreak detection. Env `JAILBREAK_DETECTION`. |
| `--pii-detection` | `true` | PII detection. Env `PII_DETECTION`. |
| `--pii-action` | `log` | `block` or `log`. `redact` is accepted but not implemented and behaves like `log`. Env `PII_ACTION`. |
| `--schema-validation` | `false` | Validate the body against the provider's request schema. Env `SCHEMA_VALIDATION`. |
| `--allowed-models` | empty (all) | Comma-separated model allowlist. Matching is by substring in either direction, so `gpt-4` also allows `gpt-4o`. Env `ALLOWED_MODELS`. |
| `--max-tokens` | `0` (no limit) | Block requests whose `max_tokens` field exceeds this. Requests without the field pass. Env `MAX_TOKENS`. |
| `--add-cost-headers` | `true` | Add `X-AI-Gateway-Cost-Estimated`. Env `ADD_COST_HEADERS`. |
| `--block-mode` | `true` | Block on prompt injection, jailbreak, PII (with `block`) and schema errors. `false` logs and tags only. Env `BLOCK_MODE`. |
| `--fail-open` | `false` | Allow a body that is not valid UTF-8 instead of answering 400. Env `FAIL_OPEN`. |
| `--rate-limit-requests` | `0` (off) | Requests per minute per client IP. Env `RATE_LIMIT_REQUESTS`. |
| `--rate-limit-tokens` | `0` (off) | Estimated tokens per minute per client IP. Env `RATE_LIMIT_TOKENS`. |
| `--verbose`, `-v` | `false` | Debug logging. Env `VERBOSE`. |

The boolean options are switches: passing the flag sets it to `true`, and
`--block-mode false` is rejected. To turn off one that defaults to `true`, use
its environment variable, e.g. `BLOCK_MODE=false` or `JAILBREAK_DETECTION=false`.

The model allowlist, the token limit and rate limits block even with
`--block-mode` off.

Full reference: <https://registry.zentinelproxy.io/ai-gateway/>

## How it works

On `request_headers` the agent detects the provider and stores it; on the last
body chunk it runs the checks in this order: schema validation, model
allowlist, `max_tokens` limit, rate limit, prompt injection, jailbreak, PII.

- **Provider detection** by path only: `/openai/deployments/` is Azure OpenAI;
  `/v1/chat/completions`, `/v1/completions` and `/v1/embeddings` are OpenAI;
  `/v1/messages` and `/v1/complete` are Anthropic. Anything else is parsed as
  OpenAI, then Anthropic, and passes if neither fits.
- **Prompt injection**: phrases such as "ignore previous instructions",
  "you are now a", "system prompt:", `[INST]`, `<<SYS>>`, and requests to
  reveal the system prompt.
- **Jailbreak**: DAN and variants, "developer mode" and similar, "bypass your
  restrictions", "hypothetically speaking". The `STAN` and `DUDE` patterns have
  no word boundaries, so ordinary words such as "understand" or "standard" match
  them; expect false positives until that is fixed.
- **PII**: email, US SSN (`123-45-6789`), US phone numbers, 16-digit card
  numbers (no Luhn check), and IPv4 addresses outside `127.`, `10.`, `192.168.`
  and `0.` (172.16/12 is reported).
- **Schema validation**: OpenAI chat completions, OpenAI legacy completions and
  Anthropic messages.
- **Token estimate**: about four characters per token, over the messages and
  system prompt. Cost estimates use a fixed per-model price table in
  `src/lib.rs` and are rough.
- **Rate limits**: a 60-second window per client IP, in memory, per agent
  process.

Headers the agent returns:

| Header | When |
|---|---|
| `X-AI-Gateway-Provider`, `X-AI-Gateway-Model`, `X-AI-Gateway-Tokens-Estimated`, `X-AI-Gateway-Cost-Estimated`, `X-AI-Gateway-PII-Detected`, `X-AI-Gateway-Schema-Valid` | Request headers on an allowed request |
| `X-RateLimit-Limit-Requests`, `X-RateLimit-Remaining-Requests`, `X-RateLimit-Limit-Tokens`, `X-RateLimit-Remaining-Tokens`, `X-RateLimit-Reset` | Response headers, when a rate limit is set |
| `X-AI-Gateway-Blocked`, `X-AI-Gateway-Blocked-Reason`, `X-AI-Gateway-Schema-Errors`, `Retry-After` | On a block |

Because these are returned with the request-body decision, Zentinel 0.6.50
does not apply them to an allowed request (it only acts on a block at that
point). The block itself, its status code and the audit tags work.

The agent reports counters (`ai_gateway_requests_total`,
`ai_gateway_requests_blocked_total`, `ai_gateway_prompt_injection_detections_total`,
`ai_gateway_pii_detections_total`, `ai_gateway_jailbreak_detections_total`) and
an `ai_gateway_in_flight_requests` gauge over the protocol.

### As a library

```rust
use zentinel_agent_ai_gateway::{AiGatewayAgent, AiGatewayConfig, PiiAction};
use zentinel_agent_protocol::v2::UdsAgentServerV2;

let config = AiGatewayConfig {
    pii_action: PiiAction::Block,
    allowed_models: vec!["gpt-4o".to_string()],
    rate_limit_requests: 60,
    ..Default::default()
};

let agent = AiGatewayAgent::new(config);
let server = UdsAgentServerV2::new("ai-gateway", "/tmp/ai.sock", Box::new(agent));
server.run().await?;
```

## Development

```bash
cargo build
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

Minimum toolchain: Rust 1.94.1 (`rust-version` in `Cargo.toml`). Building needs
`protoc` (CI installs `protobuf-compiler`).

## Related

- [Registry page](https://registry.zentinelproxy.io/ai-gateway/)
- [Agent configuration](https://docs.zentinelproxy.io/configuration/agents/)
- [Agent protocol v2](https://docs.zentinelproxy.io/agents/v2/)
- [Zentinel](https://github.com/zentinelproxy/zentinel)

## License

Apache-2.0, see [`LICENSE`](LICENSE).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
