# syntax=docker/dockerfile:1.4

# Zentinel AI Gateway Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY zentinel-ai-gateway-agent /zentinel-ai-gateway-agent

LABEL org.opencontainers.image.title="Zentinel AI Gateway Agent" \
      org.opencontainers.image.description="Zentinel AI Gateway Agent for Zentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/zentinelproxy/zentinel-agent-ai-gateway"

ENV RUST_LOG=info,zentinel_ai_gateway_agent=debug \
    SOCKET_PATH=/var/run/zentinel/ai-gateway.sock

USER nonroot:nonroot

ENTRYPOINT ["/zentinel-ai-gateway-agent"]
