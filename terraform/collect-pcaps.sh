#!/usr/bin/env bash
# Collect PCAPs from all tool instances via bastion jump host.
#
# Usage:
#   cd terraform && ./collect-pcaps.sh [output_dir]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${1:-$SCRIPT_DIR/../harness/captures/aws-$(date +%Y%m%d-%H%M%S)}"

mkdir -p "$OUTPUT_DIR"

# Get connection info from Terraform
BASTION_IP=$(terraform output -raw bastion_public_ip)
HONEYPOT_IP=$(terraform output -raw honeypot_private_ip)
TOOL_IPS=$(terraform output -json tool_private_ips)
KEY_NAME=$(terraform output -raw ssh_bastion | grep -oP '~/.ssh/\K[^.]+')
SSH_KEY="$HOME/.ssh/${KEY_NAME}.pem"

echo "Bastion: $BASTION_IP"
echo "Honeypot: $HONEYPOT_IP"
echo "Output: $OUTPUT_DIR"
echo ""

# Collect from honeypot
echo "Collecting from honeypot ($HONEYPOT_IP)..."
ssh -J "ubuntu@$BASTION_IP" -i "$SSH_KEY" -o StrictHostKeyChecking=no \
    "ubuntu@$HONEYPOT_IP" "ls /opt/harness/captures/*.pcap 2>/dev/null" | while read -r pcap; do
    scp -J "ubuntu@$BASTION_IP" -i "$SSH_KEY" -o StrictHostKeyChecking=no \
        "ubuntu@$HONEYPOT_IP:$pcap" "$OUTPUT_DIR/honeypot-$(basename "$pcap")"
done

# Collect from each tool instance
for tool in $(echo "$TOOL_IPS" | python3 -c "import json,sys; [print(k) for k in json.load(sys.stdin)]"); do
    TOOL_IP=$(echo "$TOOL_IPS" | python3 -c "import json,sys; print(json.load(sys.stdin)['$tool'])")
    echo "Collecting from $tool ($TOOL_IP)..."
    ssh -J "ubuntu@$BASTION_IP" -i "$SSH_KEY" -o StrictHostKeyChecking=no \
        "ubuntu@$TOOL_IP" "ls /opt/captures/*.pcap 2>/dev/null" 2>/dev/null | while read -r pcap; do
        scp -J "ubuntu@$BASTION_IP" -i "$SSH_KEY" -o StrictHostKeyChecking=no \
            "ubuntu@$TOOL_IP:$pcap" "$OUTPUT_DIR/${tool}-$(basename "$pcap")"
    done || echo "  No PCAPs from $tool"
done

echo ""
echo "PCAPs collected to: $OUTPUT_DIR"
ls -lh "$OUTPUT_DIR"/*.pcap 2>/dev/null || echo "No PCAPs found"
