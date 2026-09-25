#!/bin/bash
set -euo pipefail

# Install Squid proxy for domain-based LLM API filtering
apt-get update
apt-get install -y squid

# Build domain ACL from Terraform-injected list
cat > /etc/squid/allowed_domains.txt <<'DOMAINS'
%{ for domain in allowed_domains ~}
.${domain}
%{ endfor ~}
DOMAINS

# Squid configuration — CONNECT-only proxy (no SSL bump)
# Tools use HTTPS CONNECT tunnels; Squid allows/denies based on hostname
cat > /etc/squid/squid.conf <<'SQUIDCONF'
# Listen on all interfaces, port 3128
http_port 3128

# ACL: allowed LLM API domains
acl allowed_domains dstdomain "/etc/squid/allowed_domains.txt"
acl private_net dst 10.0.0.0/8

# ACL: SSL ports
acl SSL_ports port 443
acl CONNECT method CONNECT

# Allow CONNECT to allowed LLM API domains on port 443
http_access allow CONNECT SSL_ports allowed_domains

# Allow direct HTTP to private subnet (honeypot health checks, etc.)
http_access allow private_net

# Deny everything else
http_access deny all

# Logging
access_log /var/log/squid/access.log squid
cache_log /var/log/squid/cache.log

# No caching (we're just proxying API calls)
cache deny all

# Timeouts
connect_timeout 30 seconds
request_timeout 300 seconds
SQUIDCONF

systemctl enable --now squid
echo "Squid proxy ready on port 3128, allowing: ${join(", ", allowed_domains)}"
