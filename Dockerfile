FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
ARG PD_HTTPX_VERSION=1.12.0
ARG PD_HTTPX_SHA256=9d8439e8b6c9aa7d1e2314817a392e00d5178da3af5652f7475f88868f418f76

WORKDIR /srv/app
COPY requirements.txt ./
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates=20250419+deb13u1 \
        curl=8.14.1-2+deb13u7 \
        unzip=6.0-29+deb13u1 \
    && curl --fail --location --retry 3 --retry-all-errors \
        "https://github.com/projectdiscovery/httpx/releases/download/v${PD_HTTPX_VERSION}/httpx_${PD_HTTPX_VERSION}_linux_amd64.zip" \
        --output /tmp/pd-httpx.zip \
    && echo "${PD_HTTPX_SHA256}  /tmp/pd-httpx.zip" | sha256sum --check - \
    && mkdir -p /tmp/pd-httpx \
    && unzip -q /tmp/pd-httpx.zip -d /tmp/pd-httpx \
    && install -m 0555 /tmp/pd-httpx/httpx /usr/local/bin/pd-httpx \
    && apt-get purge -y curl unzip \
    && apt-get autoremove -y --purge \
    && rm -rf /var/lib/apt/lists/* /tmp/pd-httpx.zip /tmp/pd-httpx \
    && pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 10001 appuser \
    && mkdir -p /var/lib/scanner \
    && chown 10001:10001 /var/lib/scanner

COPY app ./app
USER 10001:10001
ENTRYPOINT ["python", "-m", "app.cli"]
CMD ["--help"]
