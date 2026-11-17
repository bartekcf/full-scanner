#!/bin/sh
set -eu

cat > /tmp/squid.conf <<EOF
http_port 3128
pinger_enable off
visible_hostname scanner-egress
cache deny all
cache_mem 0 MB
cache_log /dev/stderr
access_log none
pid_filename /tmp/squid.pid
coredump_dir /tmp
dns_nameservers ${EGRESS_DNS_SERVER}

acl CONNECT method CONNECT
acl SSL_ports port 443
acl Safe_ports port 80 443
acl api_clients src ${EGRESS_API_CLIENT_CIDR}
acl zap_clients src ${EGRESS_ZAP_CLIENT_CIDR}
acl scanner_clients src ${EGRESS_API_CLIENT_CIDR} ${EGRESS_ZAP_CLIENT_CIDR}
acl api_methods method GET HEAD POST CONNECT
acl zap_methods method GET HEAD CONNECT
acl non_public_dst dst "/etc/squid/non_public_ranges.txt"

http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access deny api_clients !api_methods
http_access deny zap_clients !zap_methods
http_access deny !scanner_clients
http_access deny non_public_dst
http_access allow scanner_clients
http_access deny all
EOF

squid -k parse -f /tmp/squid.conf
exec squid -N -f /tmp/squid.conf

