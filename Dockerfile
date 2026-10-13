# ==============================================================================
# IoT Risk Assessment & Response Platform - Dockerfile
# Multi-platform ready (Linux x86_64, ARM64 / Raspberry Pi, Apple Silicon)
# ==============================================================================

FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8000 \
    NO_BROWSER=true

# Install network utilities & libpcap required for Layer 2/3 packet discovery
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    net-tools \
    iproute2 \
    iptables \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency requirements first to leverage Docker layer caching
COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy platform source code
COPY . .

# Ensure data directory exists for persistent SQLite database storage
RUN mkdir -p /app/data

# Expose web application port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:8000/api/system/status || exit 1

# Launch the IoT platform
CMD ["python", "run.py", "--host", "0.0.0.0", "--port", "8000", "--no-browser"]
