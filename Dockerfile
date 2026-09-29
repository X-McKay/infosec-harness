# Backend image for the API and the Temporal worker (same image, different command).
FROM docker:29.1.3-cli AS docker-cli
FROM docker/buildx-bin:0.37.1 AS buildx
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# Only clients belong in this image; the isolated executor owns the Docker daemon.
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=buildx /buildx /usr/local/lib/docker/cli-plugins/docker-buildx
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
# Behind a TLS-inspecting proxy, drop the proxy PEM at deploy/extra-ca.crt (gitignored);
# it is added to the trust store so pip/uv/boto3 work. No-op otherwise.
COPY deploy/ /tmp/deploy/
RUN if [ -f /tmp/deploy/extra-ca.crt ]; then \
        cp /tmp/deploy/extra-ca.crt /usr/local/share/ca-certificates/extra-ca.crt \
        && update-ca-certificates; fi
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt UV_NATIVE_TLS=1

RUN pip install --no-cache-dir uv==0.12.7
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
# Install the same locked runtime dependencies used by local development and CI.
RUN uv export --locked --no-dev --no-emit-project --format requirements-txt -o /tmp/requirements.txt \
    && uv pip install --system --no-cache --require-hashes -r /tmp/requirements.txt \
    && uv pip install --system --no-cache --no-deps . \
    && rm /tmp/requirements.txt
ENV HARNESS_WORKSPACE_DIR=/workspace
CMD ["harness", "api", "--host", "0.0.0.0", "--port", "8000"]
