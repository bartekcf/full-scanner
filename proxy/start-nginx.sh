#!/bin/sh
set -eu

: "${API_DOMAIN:?API_DOMAIN is required}"
CERT_DIR="/etc/letsencrypt/live/${API_DOMAIN}"
CERT_FILE="${CERT_DIR}/fullchain.pem"
KEY_FILE="${CERT_DIR}/privkey.pem"
ACTIVE_CONFIG=/etc/nginx/conf.d/default.conf

mkdir -p /etc/nginx/conf.d /var/cache/nginx/client_temp /var/cache/nginx/proxy_temp \
    /var/cache/nginx/fastcgi_temp /var/cache/nginx/uwsgi_temp /var/cache/nginx/scgi_temp
chmod 1777 /etc/nginx/conf.d /var/cache/nginx /var/cache/nginx/* /var/run /tmp

certificate_fingerprint() {
    sha256sum "$CERT_FILE" "$KEY_FILE" | sha256sum | awk '{print $1}'
}

if [ -s "$CERT_FILE" ] && [ -s "$KEY_FILE" ]; then
    cp /etc/nginx/api.conf "$ACTIVE_CONFIG"
    last_fingerprint=$(certificate_fingerprint)
else
    cp /etc/nginx/bootstrap.conf "$ACTIVE_CONFIG"
    last_fingerprint=
fi

nginx -t
nginx -g 'daemon off;' &
nginx_pid=$!
trap 'nginx -s quit >/dev/null 2>&1 || true; wait "$nginx_pid" || true; exit 0' INT TERM

while kill -0 "$nginx_pid" 2>/dev/null; do
    if [ -s "$CERT_FILE" ] && [ -s "$KEY_FILE" ]; then
        fingerprint=$(certificate_fingerprint)
        if [ "$fingerprint" != "$last_fingerprint" ]; then
            cp /etc/nginx/api.conf "$ACTIVE_CONFIG"
            if nginx -t; then
                nginx -s reload
                last_fingerprint=$fingerprint
            fi
        fi
    fi
    sleep 10
done

wait "$nginx_pid"
