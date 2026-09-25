#!/bin/bash
set -euo pipefail

# Install Docker + dependencies
apt-get update
apt-get install -y docker.io docker-compose-v2 tcpdump tshark python3-pip git
systemctl enable --now docker

# Clone the honeypot repo
git clone https://github.com/t-0-m-1-3/fingerprinting_research_honeypot.git /opt/harness
cd /opt/harness

# Start honeypot
cd honeypot
docker compose up -d --build

# Start tcpdump capture on all interfaces (port 8443 = honeypot TLS)
mkdir -p /opt/harness/captures
nohup tcpdump -i any -s 0 -w /opt/harness/captures/llm-scan-$(date +%Y%m%d-%H%M%S).pcap \
  'tcp port ${honeypot_port}' &

echo "Honeypot ready on port ${honeypot_port}, capture running"
