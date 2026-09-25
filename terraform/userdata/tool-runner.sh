#!/bin/bash
set -euo pipefail

# Install Docker
apt-get update
apt-get install -y docker.io tcpdump
systemctl enable --now docker

# Configure proxy for all outbound HTTPS (LLM API calls)
export HTTPS_PROXY=http://${proxy_host}:${proxy_port}
export HTTP_PROXY=http://${proxy_host}:${proxy_port}
export NO_PROXY=10.0.0.0/8,localhost,127.0.0.1

# Write proxy config for Docker daemon (so docker pull works through proxy)
mkdir -p /etc/systemd/system/docker.service.d
cat > /etc/systemd/system/docker.service.d/proxy.conf <<EOF
[Service]
Environment="HTTPS_PROXY=http://${proxy_host}:${proxy_port}"
Environment="HTTP_PROXY=http://${proxy_host}:${proxy_port}"
Environment="NO_PROXY=10.0.0.0/8,localhost,127.0.0.1"
EOF
systemctl daemon-reload
systemctl restart docker

# Start local tcpdump to capture this tool's TLS handshakes
mkdir -p /opt/captures
nohup tcpdump -i any -s 0 -w /opt/captures/${tool_name}-$(date +%Y%m%d-%H%M%S).pcap \
  'tcp port 8443 or tcp port 443' &

# Pull and run the tool
# Note: Docker image must be pre-built and pushed to a registry,
# or built locally on this instance from the repo
docker run --rm \
  -e ${api_key_env_var}='${api_key}' \
  -e HTTPS_PROXY=http://${proxy_host}:${proxy_port} \
  -e HTTP_PROXY=http://${proxy_host}:${proxy_port} \
  -e NO_PROXY=10.0.0.0/8,localhost \
  --add-host=honeypot:10.0.2.10 \
  ${docker_image} \
  ${scan_command}

echo "Tool ${tool_name} completed"

# Keep instance alive for PCAP collection
sleep 300
