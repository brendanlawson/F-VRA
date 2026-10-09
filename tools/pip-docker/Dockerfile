FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl jq \
    && rm -rf /var/lib/apt/lists/*

# Snyk CLI (standalone Linux binary)
RUN curl -fsSL https://downloads.snyk.io/cli/stable/snyk-linux -o /usr/local/bin/snyk \
    && chmod +x /usr/local/bin/snyk

# uv (fast installer / resolver)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

COPY run_all.sh /run_all.sh
RUN sed -i 's/\r$//' /run_all.sh && chmod +x /run_all.sh

ENV UV_CACHE_DIR=/uvcache
ENTRYPOINT ["/run_all.sh"]
