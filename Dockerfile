# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# Keep the tag for readability and the digest for reproducibility across
# supported Docker platforms. Update both together after reviewing the
# official image manifest.
ARG PYTHON_IMAGE=python:3.12.14-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254

FROM ${PYTHON_IMAGE} AS wheel-builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

COPY requirements-build.lock ./
RUN python -m pip install --require-hashes --requirement requirements-build.lock

COPY . .

RUN python -m build --wheel --no-isolation --outdir /wheels


FROM ${PYTHON_IMAGE} AS runtime

LABEL org.opencontainers.image.title="AdversaryFlow" \
      org.opencontainers.image.description="Authorized adversary-emulation workflow planner" \
      org.opencontainers.image.source="https://github.com/rikterskale/AdversaryFlow" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="0.4.0"

ENV ADVERSARYFLOW_CACHE_DIR=/var/lib/adversaryflow/cache \
    ADVERSARYFLOW_PORT=5000 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 adversaryflow \
    && useradd --uid 10001 --gid adversaryflow --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin adversaryflow \
    && install -d -o adversaryflow -g adversaryflow /var/lib/adversaryflow/cache /run/adversaryflow

COPY requirements.lock ./
RUN python -m pip install --require-hashes --requirement requirements.lock

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
CMD ["serve", "--host", "0.0.0.0", "--port", "5000", "--allow-remote"]
