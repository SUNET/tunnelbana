# syntax=docker/dockerfile:1
#
# Production image for the tunnelbana identity proxy.
#
# Multi-stage: the release binary is compiled on Debian 13 (trixie) so its
# glibc matches the trixie-slim runtime, then copied into a minimal,
# non-root runtime image with no Rust toolchain. All dependencies
# (grindvakt, jose-rs, gamlastan, …) resolve from crates.io — there are no
# path overrides — so the build is fully self-contained.
#
# Build:  docker build -t tunnelbana:latest .
# Run:    docker run --rm -p 8080:8080 \
#           -e TUNNELBANA_STATE_KEY="$(openssl rand -base64 48)" \
#           -v "$PWD/config:/app/config:ro" -v "$PWD/keys:/app/keys:ro" \
#           tunnelbana:latest

# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — build
# ─────────────────────────────────────────────────────────────────────────────
FROM rust:1-trixie AS build

WORKDIR /src
COPY . .

# Cache mounts keep the crates.io registry and the target dir warm across
# builds; the binary is copied out of the (ephemeral) cache-mounted target dir
# within the same layer. `--locked` builds exactly what Cargo.lock pins.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p tunnelbana \
 && cp /src/target/release/tunnelbana /usr/local/bin/tunnelbana

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — runtime
# ─────────────────────────────────────────────────────────────────────────────
FROM debian:trixie-slim AS runtime

# ca-certificates: outbound TLS to MDQ / federation / JWKS endpoints.
# curl: container HEALTHCHECK only.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl less \
 && rm -rf /var/lib/apt/lists/*

# Run as an unprivileged system user.
RUN useradd --system --uid 10001 --user-group --no-create-home tunnelbana

WORKDIR /app
COPY --from=build /usr/local/bin/tunnelbana /usr/local/bin/tunnelbana
# Baked default config so the image runs standalone; bind-mount /app/config to
# override with a deployment's proxy.toml / attributes.toml. Keys and secrets
# are NEVER baked — mount /app/keys and pass secrets via env at runtime.
COPY config/ /app/config/

ENV TUNNELBANA_BIND=0.0.0.0:8080
EXPOSE 8080
USER tunnelbana

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:8080/health" || exit 1

# actix-web handles SIGTERM for graceful shutdown, so it runs fine as PID 1.
ENTRYPOINT ["tunnelbana"]
CMD ["/app/config/proxy.toml"]
