FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ssh \
    openssh-client \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Bitwarden CLI
# Pinned version for supply-chain integrity; update BW_VERSION to upgrade.
# Set BW_SHA256 to verify the downloaded archive (get it from the GitHub release page).
ENV BW_VERSION=2025.5.0
ARG BW_SHA256=""
RUN curl -fsSL -o /tmp/bw.zip "https://github.com/bitwarden/clients/releases/download/cli-v${BW_VERSION}/bw-linux-${BW_VERSION}.zip" \
    && if [ -n "$BW_SHA256" ]; then echo "$BW_SHA256  /tmp/bw.zip" | sha256sum -c -; fi \
    && unzip -o /tmp/bw.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/bw \
    && test -x /usr/local/bin/bw \
    && rm /tmp/bw.zip \
    && apt-get purge -y --auto-remove unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY rotate_keys.yaml .

# Bundle PicoCSS locally so the app works without CDN access
ENV PICO_VERSION=2.0.6
RUN curl -fsSL "https://cdn.jsdelivr.net/npm/@picocss/pico@${PICO_VERSION}/css/pico.min.css" \
    -o src/static/pico.min.css

# Create non-root user and ensure data directory is writable
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser \
    && mkdir -p /app/data \
    && chown -R appuser:appuser /app/data /app/src /app/rotate_keys.yaml

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["python", "-m", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]