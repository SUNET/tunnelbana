# Runtime-only image — NO Rust toolchain, so the remote never compiles.
#
# The binary is cross-built on the dev host inside a debian-13 (trixie) container
# (see build.sh) so its glibc matches this base, then shipped via rsync into
# ./bin. docker-compose bind-mounts ./bin, ./config and ./keys, so the usual
# iteration is: build.sh -> rsync bin/tunnelbana -> `docker compose restart`.
FROM debian:13-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl python3.13 libpython3.13 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# The image contains only non-secret build inputs. Identity keys must be
# mounted at runtime; putting them in COPY would retain them in an image layer
# even if a later layer removed them.
COPY proxy.toml /app/config/proxy.toml
ENV TUNNELBANA_BIND=0.0.0.0:8080
EXPOSE 8080
CMD ["/app/bin/tunnelbana", "config/proxy.toml"]
