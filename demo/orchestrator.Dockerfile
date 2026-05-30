# Runtime-only image for the orchestrator (Tier 0 + trust engine).
#
# The waf-proxy binary is compiled SEPARATELY by the Makefile `proxy` target, in
# a golang:bookworm container with a persistent Go build cache (named volumes),
# so rebuilds are incremental (~10s). We do this instead of an in-image
# `go build` because this host has no BuildKit/buildx, so Dockerfile cache mounts
# are unavailable and a plain in-image build recompiles everything (~6min) every
# time. golang:1.26-bookworm and debian:bookworm-slim share glibc 2.36, so the
# CGO binary (go-sqlite3) runs here unchanged.
#
# Build context is the repo root. Run `make proxy` (or `make up` / `make orch`)
# before building this image so demo/bin/waf-proxy exists.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY tier-0/model/ /app/model/
COPY demo/bin/waf-proxy /app/waf-proxy
RUN chmod +x /app/waf-proxy
ENV REDIS_ADDR=redis:6379
EXPOSE 8080 8081
# -threshold 0.99: front ML tier permissive by default so exploits reach the
# backend and the RASP (Tier 2) is demonstrable. Restore a tighter threshold and
# enable Coraza from the dashboard Settings for the full payload-blocking cascade.
CMD ["/app/waf-proxy", "-backend", "http://target:9090", "-model-dir", "/app/model", "-listen", ":8080", "-threshold", "0.99"]
