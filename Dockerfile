# syntax=docker/dockerfile:1.4

# Sentinel AI Gateway Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY sentinel-ai-gateway-agent /sentinel-ai-gateway-agent

LABEL org.opencontainers.image.title="Sentinel AI Gateway Agent" \
      org.opencontainers.image.description="Sentinel AI Gateway Agent for Sentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/raskell-io/sentinel-agent-ai-gateway"

ENV RUST_LOG=info,sentinel_ai_gateway_agent=debug \
    SOCKET_PATH=/var/run/sentinel/ai-gateway.sock

USER nonroot:nonroot

ENTRYPOINT ["/sentinel-ai-gateway-agent"]
