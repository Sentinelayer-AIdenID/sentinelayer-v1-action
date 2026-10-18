# syntax=docker/dockerfile:1

# Stage 1: Builder (install Python deps into a clean prefix)
FROM python:3.11-alpine@sha256:303398d5c9f110790bce60d64f902e51e1a061e33292985c72bf6cd07960bf09 AS builder

RUN set -eux; \
    apk add --no-cache \
      build-base=0.5-r3 \
      libffi-dev=3.5.2-r0 \
      openssl-dev=3.5.9-r0 \
      cargo=1.91.1-r2 \
    && python -m pip install --upgrade pip wheel

WORKDIR /tmp
COPY requirements.lock.txt /tmp/requirements.lock.txt

RUN python -m pip install --no-cache-dir --prefix=/install --require-hashes -r /tmp/requirements.lock.txt

# Stage 2: Runtime (runs as root in ephemeral container)
FROM python:3.11-alpine@sha256:303398d5c9f110790bce60d64f902e51e1a061e33292985c72bf6cd07960bf09 AS runtime

RUN set -eux; \
    apk add --no-cache \
      ca-certificates=20251003-r0 \
      libstdc++=15.2.0-r2 \
      nodejs=24.18.1-r0 \
      npm=11.11.0-r0 \
      openssl=3.5.9-r0 \
      git=2.52.0-r0

# Install Codex CLI (pinned) with npm dist.integrity verification.
ARG CODEX_CLI_PACKAGE=@openai/codex
ARG CODEX_CLI_VERSION=0.98.0
RUN set -eux; \
    expected_integrity="$(npm view "${CODEX_CLI_PACKAGE}@${CODEX_CLI_VERSION}" dist.integrity --json | tr -d '"')"; \
    if [ -z "${expected_integrity}" ]; then \
      echo "Unable to resolve npm dist.integrity for ${CODEX_CLI_PACKAGE}@${CODEX_CLI_VERSION}" >&2; \
      exit 1; \
    fi; \
    tmpdir="$(mktemp -d)"; \
    npm pack "${CODEX_CLI_PACKAGE}@${CODEX_CLI_VERSION}" --pack-destination "${tmpdir}" >/dev/null; \
    tarball="$(ls "${tmpdir}"/*.tgz)"; \
    actual_integrity="sha512-$(openssl dgst -sha512 -binary "${tarball}" | openssl base64 -A)"; \
    if [ "${actual_integrity}" != "${expected_integrity}" ]; then \
      echo "Integrity mismatch for ${CODEX_CLI_PACKAGE}@${CODEX_CLI_VERSION}" >&2; \
      echo "expected=${expected_integrity} actual=${actual_integrity}" >&2; \
      exit 1; \
    fi; \
    npm install -g "${tarball}"; \
    rm -rf "${tmpdir}"; \
    npm cache clean --force

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    NODE_ENV=production

COPY --from=builder /install /usr/local
COPY src /app/src
COPY prompts /app/prompts
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

# Run as root. GitHub Actions mounts /github/workspace, /github/file_commands,
# and other paths owned by the host runner UID. Dropping to a non-root user
# breaks post-step writes (GITHUB_OUTPUT, GITHUB_STEP_SUMMARY) because the
# runner process loses access to its own file_commands directory after our step.
# This is an ephemeral container — it is destroyed after the job step.
# omargate:allow-root-user

ENTRYPOINT ["/app/entrypoint.sh"]
