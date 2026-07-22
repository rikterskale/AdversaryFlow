FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

COPY examples ./examples
COPY data ./data

RUN useradd --create-home --uid 10001 adversaryflow \
    && mkdir /work \
    && chown adversaryflow:adversaryflow /work

USER adversaryflow
WORKDIR /work

ENTRYPOINT ["adversaryflow"]
CMD ["--help"]
