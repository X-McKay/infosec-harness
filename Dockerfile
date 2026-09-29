# Backend image for the API and the Temporal worker (same image, different command).
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# Docker CLI lets the worker drive the sandbox daemon via the mounted socket.
RUN apt-get update && apt-get install -y --no-install-recommends docker.io ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Behind a TLS-inspecting proxy, drop the proxy PEM at deploy/extra-ca.crt (gitignored);
# it is added to the trust store so pip/uv/boto3 work. No-op otherwise.
COPY deploy/ /tmp/deploy/
RUN if [ -f /tmp/deploy/extra-ca.crt ]; then \
        cp /tmp/deploy/extra-ca.crt /usr/local/share/ca-certificates/extra-ca.crt \
        && update-ca-certificates; fi
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt UV_NATIVE_TLS=1

RUN pip install --no-cache-dir uv
COPY pyproject.toml uv.lock* ./
COPY src ./src
RUN uv pip install --system --no-cache .
ENV HARNESS_WORKSPACE_DIR=/workspace
CMD ["harness", "api", "--host", "0.0.0.0", "--port", "8000"]
