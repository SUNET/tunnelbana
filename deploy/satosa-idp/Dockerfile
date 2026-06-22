# Runtime-only image — NO Rust toolchain, so the remote never compiles.
#
# The binary is cross-built on the dev host inside a debian-13 (trixie) container
# (see build.sh) so its glibc matches this base, then shipped via rsync into
# ./bin. docker-compose bind-mounts ./bin, ./config and ./keys, so the usual
# iteration is: build.sh -> rsync bin/tunnelbana -> `docker compose restart`.
FROM debian:13-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Baked copies so the image also runs standalone; bind mounts override at runtime.
COPY bin/ /app/bin/
COPY config/ /app/config/
COPY keys/ /app/keys/
ENV TUNNELBANA_BIND=0.0.0.0:8080
EXPOSE 8080
CMD ["/app/bin/tunnelbana", "config/proxy.toml"]
