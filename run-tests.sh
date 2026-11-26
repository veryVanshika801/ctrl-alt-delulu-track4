#!/usr/bin/env bash
# run-tests: execute tests in Docker container or local environment with sandbox constraints
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if command -v docker >/dev/null 2>&1; then
    echo "[Containerized Test Run]"
    docker build -t ctrl-alt-delulu-track4:latest .
    echo "Running with --read-only and --network none..."
    docker run --rm \
        --read-only \
        --tmpfs /tmp:rw,nosuid,size=64m \
        --network none \
        -e TRACK4_STATE_DIR=/tmp/track4-state \
        ctrl-alt-delulu-track4:latest \
        node --test --test-concurrency=1 tests/*.cjs
else
    echo "[Local Host Test Run]"
    export TRACK4_STATE_DIR="$(mktemp -d /tmp/track4-test-XXXXXX)"
    echo "Using temporary TRACK4_STATE_DIR: $TRACK4_STATE_DIR"
    node --test --test-concurrency=1 tests/*.cjs
    rm -rf "$TRACK4_STATE_DIR"
fi
