#!/bin/bash
set -euo pipefail

# Install Docker and AWS CLI (for ECR login)
apt-get update
apt-get install -y docker.io tcpdump awscli
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

# Write API key to a file (not on command line — avoids ps/audit log exposure)
ENVFILE=$(mktemp /tmp/tool-env.XXXXXX)
chmod 600 "$ENVFILE"
cat > "$ENVFILE" <<ENVEOF
${api_key_env_var}=${api_key}
HTTPS_PROXY=http://${proxy_host}:${proxy_port}
HTTP_PROXY=http://${proxy_host}:${proxy_port}
NO_PROXY=10.0.0.0/8,localhost
ENVEOF

# Authenticate to ECR and pull tool image
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
aws ecr get-login-password --region "$REGION" | \
  docker login --username AWS --password-stdin "$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com"
docker run --rm \
  --env-file "$ENVFILE" \
  --add-host=honeypot:10.0.2.10 \
  ${docker_image} \
  ${scan_command}

# Clean up secrets
rm -f "$ENVFILE"

echo "Tool ${tool_name} completed"

# Keep instance alive for PCAP collection
sleep 300
