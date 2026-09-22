# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# Keep the tag for readability and the digest for reproducibility across
# supported Docker platforms. Update both together after reviewing the
# official image manifest.
ARG PYTHON_IMAGE=python:3.12.14-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254
ARG NODE_IMAGE=node:24.15.0-bookworm-slim@sha256:4e6b70dd6cbfc88c8157ba19aa3d9f9cce6ba4703576d55459e45efcbc9c5f5d

FROM ${NODE_IMAGE} AS frontend-builder

ENV NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_UPDATE_NOTIFIER=false

WORKDIR /build

# Install exactly the browser dependency graph reviewed in package-lock.json.
# Lifecycle scripts are not needed to build this application.
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

COPY frontend ./frontend
RUN npm run build:frontend

FROM ${PYTHON_IMAGE} AS wheel-builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

COPY requirements-build.lock ./
RUN python -m pip install --require-hashes --requirement requirements-build.lock

COPY . .
# Never trust a stale checked-in browser bundle: the image packages the SPA
# compiled in the pinned Node stage above.
COPY --from=frontend-builder /build/frontend/index.html ./frontend/index.html
COPY --from=frontend-builder /build/frontend/styles.css ./frontend/styles.css
COPY --from=frontend-builder /build/frontend/app.js ./frontend/app.js
COPY --from=frontend-builder /build/frontend/favicon.svg ./frontend/favicon.svg

RUN python -m build --wheel --no-isolation --outdir /wheels


FROM ${PYTHON_IMAGE} AS runtime

LABEL org.opencontainers.image.title="AdversaryFlow" \
      org.opencontainers.image.description="Authorized adversary-emulation workflow planner" \
      org.opencontainers.image.source="https://github.com/rikterskale/AdversaryFlow" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="0.5.2"

ENV ADVERSARYFLOW_CACHE_DIR=/var/lib/adversaryflow/cache \
    ADVERSARYFLOW_HOST=0.0.0.0 \
    ADVERSARYFLOW_PORT=5000 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 adversaryflow \
    && useradd --uid 10001 --gid adversaryflow --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin adversaryflow \
    && install -d -o adversaryflow -g adversaryflow /var/lib/adversaryflow/cache /run/adversaryflow

COPY requirements.lock /tmp/requirements.lock
RUN python -m pip install --require-hashes --requirement /tmp/requirements.lock \
    && rm -f /tmp/requirements.lock

COPY --from=wheel-builder /wheels /wheels
COPY --from=wheel-builder /build/ACCEPTABLE_USE.md /usr/share/doc/adversaryflow/ACCEPTABLE_USE.md
RUN python -m pip install --no-deps /wheels/adversaryflow-*.whl \
    && rm -rf /wheels

COPY --chown=root:root docker/entrypoint.sh /usr/local/bin/adversaryflow-entrypoint
COPY --chown=root:root docker/healthcheck.py /usr/local/lib/adversaryflow/container_healthcheck.py
RUN chmod 0555 /usr/local/bin/adversaryflow-entrypoint /usr/local/lib/adversaryflow/container_healthcheck.py

USER 10001:10001
WORKDIR /var/lib/adversaryflow

EXPOSE 5000

HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=60 \
    CMD ["python", "/usr/local/lib/adversaryflow/container_healthcheck.py"]

ENTRYPOINT ["/usr/local/bin/adversaryflow-entrypoint"]
CMD ["serve", "--allow-remote"]
