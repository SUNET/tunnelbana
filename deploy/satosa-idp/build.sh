#!/usr/bin/env bash
# Cross-build the tunnelbana release binary for the satosa-idp deployment.
#
# Builds inside a debian-13 (trixie) Rust container so the produced binary's
# glibc matches the runtime image (debian:13-slim). Shares the trixie target dir
# with deploy/tunnelbana(-sp) — same base, same binary. The target dir and the
# host cargo registry are mounted so rebuilds are incremental and offline-ish.
#
# Output: <workspace>/.build-cache/target-trixie/release/tunnelbana
# Ship it with:  rsync -a <that path> debian@realta.labb.sunet.se:~/tunnelbana-idp/bin/tunnelbana
#                ssh debian@realta.labb.sunet.se 'cd ~/tunnelbana-idp && docker compose restart'
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"   # tunnelbana workspace root
cd "$REPO"
mkdir -p .build-cache/target-trixie
docker run --rm \
  -v "$REPO":/src \
  -v "$REPO/.build-cache/target-trixie":/src/target \
  -v "$HOME/.cargo/registry":/usr/local/cargo/registry \
  -w /src rust:1-trixie \
  bash -c 'export PATH=/usr/local/cargo/bin:$PATH; \
           apt-get update -qq && apt-get install -y -qq perl >/dev/null 2>&1; \
           cargo build --release -p tunnelbana'
echo "binary: $REPO/.build-cache/target-trixie/release/tunnelbana"
