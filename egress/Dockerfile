FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        squid=5.7-2+deb12u6 \
        netcat-openbsd=1.219-1 \
        ca-certificates=20250419~deb12u2 \
    && rm -rf /var/lib/apt/lists/*

COPY egress/entrypoint.sh /usr/local/bin/egress-entrypoint
COPY app/non_public_ranges.txt /etc/squid/non_public_ranges.txt
RUN chmod 0555 /usr/local/bin/egress-entrypoint \
    && chmod 0444 /etc/squid/non_public_ranges.txt

USER proxy
EXPOSE 3128
HEALTHCHECK --interval=5s --timeout=3s --retries=12 CMD nc -z 127.0.0.1 3128 || exit 1
ENTRYPOINT ["/usr/local/bin/egress-entrypoint"]
