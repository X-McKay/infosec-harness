# Backend image for the API and the Temporal worker (same image, different command).
# Every base is pinned by version and digest. The Python and uv versions must equal .mise.toml;
# tests/development/test_dev_experience.py checks that they do.
FROM docker:29.1.3-cli@sha256:4fa0ee1f3a7e4354c4ea34558b6d4ee32859baf4973d4c8ccc8e7fe3dd730c04 AS docker-cli
FROM docker/buildx-bin:0.37.1@sha256:0ef4e936b9057e45a8c6595c01a8116353acd102b6a5720af7c3bcb50346e2ca AS buildx
FROM ghcr.io/astral-sh/uv:0.12.7@sha256:95f2aa1fe59274951cfe9b0cbc7972e879ff1004bc8945d130a32eb0dbd85945 AS uv
FROM python:3.12.13-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# Only clients belong in this image; the isolated executor owns the Docker daemon.
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=buildx /buildx /usr/local/lib/docker/cli-plugins/docker-buildx
COPY --from=uv /uv /uvx /usr/local/bin/
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
# Behind a TLS-inspecting proxy, drop the proxy PEM at deploy/extra-ca.crt (gitignored);
# it is added to the trust store so uv/boto3 work. No-op otherwise. .dockerignore admits only
# that one file from deploy/, and the context is bind-mounted for this step, not copied in.
RUN --mount=type=bind,target=/tmp/context \
    if [ -f /tmp/context/deploy/extra-ca.crt ]; then \
        cp /tmp/context/deploy/extra-ca.crt /usr/local/share/ca-certificates/extra-ca.crt \
        && update-ca-certificates; fi
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt UV_NATIVE_TLS=1

COPY pyproject.toml uv.lock README.md ./
COPY src ./src
# Install the same locked runtime dependencies used by local development and CI.
RUN uv export --locked --no-dev --no-emit-project --format requirements-txt -o /tmp/requirements.txt \
    && uv pip install --system --no-cache --require-hashes -r /tmp/requirements.txt \
    && uv pip install --system --no-cache --no-deps . \
    && rm /tmp/requirements.txt
ENV HARNESS_WORKSPACE_DIR=/workspace
CMD ["harness", "api", "--host", "0.0.0.0", "--port", "8000"]
