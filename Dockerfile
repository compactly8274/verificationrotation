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
RUN curl -L -o /tmp/bw.zip "https://github.com/bitwarden/clients/releases/download/cli-v2024.12.0/bw-linux-2024.12.0.zip" \
    && unzip -o /tmp/bw.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/bw \
    && rm /tmp/bw.zip

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY rotate_keys.yaml .

# Ensure data directory exists
RUN mkdir -p /app/data

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["python", "-m", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
