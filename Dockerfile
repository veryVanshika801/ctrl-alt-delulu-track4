# Dockerfile matching the Track 4 judging environment
# Linux container with Node.js 24.11.1, Python 3.12, and pqcrypto
FROM node:24.11.1-bookworm-slim

# Install Python 3.12 and build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install pqcrypto for interop verification
RUN pip3 install --no-cache-dir --break-system-packages "pqcrypto==0.4.0"

WORKDIR /workspace

# Copy submission
COPY . /workspace/

ENV TRACK4_STATE_DIR=/tmp/track4-state

CMD ["node", "track4_service.cjs"]
