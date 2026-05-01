# syntax=docker/dockerfile:1

# Stage 1 — Build all three components
FROM golang:1.26-bookworm AS builder

# System deps for Python + Node
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip curl nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

WORKDIR /build
COPY . .

# Build everything (gateway binary + Python CLI venv + TypeScript plugin)
RUN NO_QUICKSTART=1 NO_LLM_SETUP=1 make install

# Stage 2 — Minimal runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install uv for runtime Python env
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:/root/.local/bin:$PATH"

# Copy built artifacts from builder
COPY --from=builder /root/.local/bin/defenseclaw /usr/local/bin/defenseclaw
COPY --from=builder /root/.local/bin/defenseclaw-gateway /usr/local/bin/defenseclaw-gateway
COPY --from=builder /root/.defenseclaw/extensions /root/.defenseclaw/extensions

# Copy Python venv
COPY --from=builder /build/.venv /opt/defenseclaw/venv
ENV PATH="/opt/defenseclaw/venv/bin:$PATH"

# Copy policies and schemas
COPY --from=builder /build/policies /opt/defenseclaw/policies
COPY --from=builder /build/schemas  /opt/defenseclaw/schemas

# Guardrail proxy port | Sidecar REST API port
EXPOSE 4000 18970

# Data directory — mount a volume here to persist audit.db and config
VOLUME ["/root/.defenseclaw"]

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["start"]
