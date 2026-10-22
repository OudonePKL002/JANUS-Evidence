# ==============================================================================
# JANUS-Evidence ARM64-Compatible Dockerfile
# Supports multi-arch builds natively on Apple Silicon (linux/arm64)
# ==============================================================================
FROM python:3.11-slim-bookworm

LABEL maintainer="Software Security Laboratory, Sangji University"
LABEL description="JANUS-Evidence: Evidence-Grounded Multi-Agent Vulnerability Localization, RCA, and Exploit Validation"

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    FOUNDRY_DIR="/root/.foundry" \
    PATH="/root/.foundry/bin:${PATH}"

# Install system dependencies, Node.js, npm, and build essentials (architecture-agnostic)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    jq \
    ca-certificates \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Install Foundry toolchain (forge, cast, anvil, chisel) via foundryup
# Automatically detects target architecture (aarch64 / arm64 on Apple Silicon)
RUN curl -L https://foundry.paradigm.xyz | bash \
    && /root/.foundry/bin/foundryup \
    && forge --version \
    && cast --version \
    && anvil --version

WORKDIR /workspace

# Install Python dependencies first for layer caching
COPY requirements.txt /workspace/requirements.txt
RUN pip install --upgrade pip setuptools wheel \
    && pip install -r /workspace/requirements.txt

# Copy project source
COPY . /workspace

CMD ["pytest", "-v", "tests/"]

