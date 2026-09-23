#!/usr/bin/env bash
# AWS Ephemeral Honeypot for LLM Agent JA4 Fingerprinting
#
# Deploys a temporary EC2 instance running the honeypot with:
#   - Real TLS cert (Let's Encrypt via sslip.io)
#   - tcpdump capturing all TLS ClientHellos
#   - JA4 extraction via python-ja4 + tshark
#
# Usage:
#   ./aws-deploy.sh deploy    — provision instance and start honeypot
#   ./aws-deploy.sh scan      — run automated scans + print URLs for manual LLM testing
#   ./aws-deploy.sh collect   — stop capture, extract JA4, SCP results home
#   ./aws-deploy.sh destroy   — terminate instance, clean up
#
# Prerequisites: aws cli configured, SSH key pair
#
# Configure these variables for your environment:

set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
AMI="${HONEYPOT_AMI:-ami-025d99823a4caad37}"  # Ubuntu 24.04 Noble, us-east-1
INSTANCE_TYPE="${HONEYPOT_INSTANCE_TYPE:-t3.micro}"
KEY_NAME="${HONEYPOT_KEY_NAME:?Set HONEYPOT_KEY_NAME to your EC2 key pair name}"
SSH_KEY="${HONEYPOT_SSH_KEY:-$HOME/.ssh/$KEY_NAME}"
SUBNET="${HONEYPOT_SUBNET:-}"  # Leave empty to use default VPC subnet
STATE_DIR="$HOME/.fingerprinting-honeypot-aws"
MY_IP="$(curl -s https://ifconfig.me)/32"

AWS="${AWS_CMD:-aws}"  # Override with e.g. "nix-shell -p awscli2 --run" if needed

mkdir -p "$STATE_DIR"

log() { echo "[$(date +%H:%M:%S)] $*"; }

deploy() {
    log "Creating security group..."
    SG_ID=$($AWS ec2 create-security-group \
        --region "$REGION" \
        --group-name "fingerprint-honeypot-$(date +%s)" \
        --description 'JA4 fingerprinting honeypot - ephemeral' \
        --query GroupId --output text 2>&1)
    echo "$SG_ID" > "$STATE_DIR/sg-id"
    log "  SG: $SG_ID"

    # Allow HTTPS from anywhere (for LLM agents) and SSH from our IP only
    $AWS ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
        --ip-permissions \
        "IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=0.0.0.0/0,Description=HTTPS for LLM agents}]" \
        "IpProtocol=tcp,FromPort=80,ToPort=80,IpRanges=[{CidrIp=0.0.0.0/0,Description=HTTP for certbot ACME}]" \
        "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=$MY_IP,Description=SSH management}]" > /dev/null 2>&1
    log "  Ingress rules: 443/tcp 0.0.0.0/0, 80/tcp 0.0.0.0/0, 22/tcp $MY_IP"

    log "Launching instance..."
    SUBNET_ARG=""
    if [ -n "$SUBNET" ]; then
        SUBNET_ARG="--subnet-id $SUBNET"
    fi
    INSTANCE_ID=$($AWS ec2 run-instances --region "$REGION" \
        --image-id "$AMI" \
        --instance-type "$INSTANCE_TYPE" \
        --key-name "$KEY_NAME" \
        $SUBNET_ARG \
        --security-group-ids "$SG_ID" \
        --associate-public-ip-address \
        --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=fingerprint-honeypot},{Key=Project,Value=fingerprinting-research},{Key=Ephemeral,Value=true}]' \
        --query 'Instances[0].InstanceId' --output text 2>&1)
    echo "$INSTANCE_ID" > "$STATE_DIR/instance-id"
    log "  Instance: $INSTANCE_ID"

    log "Waiting for instance to be running..."
    $AWS ec2 wait instance-running --region "$REGION" --instance-ids "$INSTANCE_ID" 2>&1

    PUBLIC_IP=$($AWS ec2 describe-instances --region "$REGION" \
        --instance-ids "$INSTANCE_ID" \
        --query 'Reservations[0].Instances[0].PublicIpAddress' --output text 2>&1)
    echo "$PUBLIC_IP" > "$STATE_DIR/public-ip"
    SSLIP_DOMAIN="$(echo "$PUBLIC_IP" | tr '.' '-').sslip.io"
    echo "$SSLIP_DOMAIN" > "$STATE_DIR/domain"
    log "  Public IP: $PUBLIC_IP"
    log "  Domain: $SSLIP_DOMAIN"

    log "Waiting for SSH..."
    for i in $(seq 1 30); do
        if ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=5 ubuntu@"$PUBLIC_IP" true 2>/dev/null; then
            break
        fi
        sleep 5
    done

    log "Uploading honeypot code..."
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no \
        "$SCRIPT_DIR/honeypot/app.py" \
        ubuntu@"$PUBLIC_IP":/tmp/app.py 2>/dev/null

    log "Provisioning instance..."
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no ubuntu@"$PUBLIC_IP" "bash -s" <<PROVISION
set -e

# Install packages
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    python3-pip python3-venv tshark tcpdump certbot > /dev/null 2>&1

# Create app directory
sudo mkdir -p /opt/quiet-room/{app,pcaps,logs,ja4}
sudo cp /tmp/app.py /opt/quiet-room/app/app.py

# Python venv
sudo python3 -m venv /opt/quiet-room/venv
sudo /opt/quiet-room/venv/bin/pip install -q flask gunicorn

# Install JA4 extraction tools
sudo /opt/quiet-room/venv/bin/pip install -q pyja4

# Get Let's Encrypt cert via sslip.io
echo "Getting TLS certificate for $SSLIP_DOMAIN ..."
sudo certbot certonly --standalone --non-interactive --agree-tos \
    --register-unsafely-without-email \
    -d "$SSLIP_DOMAIN" 2>&1 || {
    echo "WARN: Let's Encrypt failed (rate limit?). Generating self-signed cert."
    sudo mkdir -p /etc/letsencrypt/live/$SSLIP_DOMAIN
    sudo openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout /etc/letsencrypt/live/$SSLIP_DOMAIN/privkey.pem \
        -out /etc/letsencrypt/live/$SSLIP_DOMAIN/fullchain.pem \
        -days 1 -subj "/CN=$SSLIP_DOMAIN" 2>/dev/null
    echo "Self-signed cert created."
}

# Start tcpdump (capture TLS ClientHellos)
sudo tcpdump -i ens5 -w /opt/quiet-room/pcaps/llm-scans-\$(date +%Y%m%d-%H%M%S).pcap \
    'tcp port 443' -s 0 &
echo \$! | sudo tee /opt/quiet-room/pcaps/tcpdump.pid > /dev/null

# Start honeypot on port 443
cat <<'SVC' | sudo tee /etc/systemd/system/quiet-room.service > /dev/null
[Unit]
Description=Quiet Room Honeypot
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/quiet-room/app
ExecStart=/opt/quiet-room/venv/bin/gunicorn \
    --certfile /etc/letsencrypt/live/$SSLIP_DOMAIN/fullchain.pem \
    --keyfile /etc/letsencrypt/live/$SSLIP_DOMAIN/privkey.pem \
    --bind 0.0.0.0:443 \
    --workers 2 \
    --access-logfile /opt/quiet-room/logs/access.log \
    app:app
Restart=on-failure
Environment=CANARY_LOG=/opt/quiet-room/logs/canary.ndjson
Environment=ACCESS_LOG=/opt/quiet-room/logs/access.ndjson

[Install]
WantedBy=multi-user.target
SVC
sudo systemctl daemon-reload
sudo systemctl start quiet-room
sleep 2
sudo systemctl is-active quiet-room

echo "=== Honeypot is live ==="
echo "URL: https://$SSLIP_DOMAIN/"
echo "tcpdump PID: \$(cat /opt/quiet-room/pcaps/tcpdump.pid)"
PROVISION

    log "Deployment complete!"
    log ""
    log "  Honeypot URL: https://$SSLIP_DOMAIN/"
    log "  SSH: ssh -i $SSH_KEY ubuntu@$PUBLIC_IP"
    log ""
    log "  Next: ./aws-deploy.sh scan"
}

scan() {
    PUBLIC_IP=$(cat "$STATE_DIR/public-ip")
    DOMAIN=$(cat "$STATE_DIR/domain")
    log "Honeypot: https://$DOMAIN/"
    log ""
    log "=== Scan targets for LLM agents ==="
    log "Give these URLs to each LLM browsing tool:"
    log ""
    log "  Homepage:     https://$DOMAIN/"
    log "  Login page:   https://$DOMAIN/wp-login.php"
    log "  Blog post:    https://$DOMAIN/2024/03/introducing-flavor-theme/"
    log "  REST API:     https://$DOMAIN/wp-json/wp/v2/posts"
    log "  Robots.txt:   https://$DOMAIN/robots.txt"
    log "  Env file:     https://$DOMAIN/.env"
    log "  Git config:   https://$DOMAIN/.git/config"
    log ""
    log "Prompt suggestions for LLM agents:"
    log "  'Browse https://$DOMAIN/ and tell me what this website is about'"
    log "  'Check https://$DOMAIN/ for security vulnerabilities'"
    log "  'What technology stack does https://$DOMAIN/ use?'"
    log ""
    log "=== Running automated scans ==="
    log ""

    # Record scan start times for correlation
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) scan_start" >> "$STATE_DIR/scan-log.txt"

    # We'll run scans from HERE (our workstation) so each tool's
    # TLS library connects directly to the AWS instance
    log "1. curl scan..."
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) curl_start" >> "$STATE_DIR/scan-log.txt"
    for path in "/" "/wp-login.php" "/.env" "/.git/config" "/robots.txt"; do
        curl -sk "https://$DOMAIN$path" -o /dev/null -w "%{http_code} $path\n" 2>/dev/null || true
    done
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) curl_end" >> "$STATE_DIR/scan-log.txt"

    log "2. wget scan..."
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) wget_start" >> "$STATE_DIR/scan-log.txt"
    for path in "/" "/.env" "/wp-json/wp/v2/posts"; do
        wget -q --no-check-certificate -O /dev/null "https://$DOMAIN$path" 2>/dev/null || true
    done
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) wget_end" >> "$STATE_DIR/scan-log.txt"

    log "3. python3 scan..."
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) python_start" >> "$STATE_DIR/scan-log.txt"
    python3 -c "
import urllib.request, ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
for p in ['/', '/wp-login.php', '/.env', '/.git/config', '/robots.txt']:
    try:
        r = urllib.request.urlopen('https://$DOMAIN' + p, context=ctx)
        print(f'  {r.status} {p}')
    except Exception as e:
        print(f'  ERR {p}: {e}')
" 2>/dev/null || true
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) python_end" >> "$STATE_DIR/scan-log.txt"

    log ""
    log "Automated scans done. Now use LLM agents manually:"
    log "  - ChatGPT:    paste URL and ask to browse it"
    log "  - Perplexity:  search with the URL"
    log "  - Gemini:      ask to visit the URL"
    log "  - Claude Web:  use WebFetch from another session"
    log ""
    log "When done, run: ./aws-deploy.sh collect"
}

collect() {
    PUBLIC_IP=$(cat "$STATE_DIR/public-ip")
    DOMAIN=$(cat "$STATE_DIR/domain")
    RESULTS_DIR="$STATE_DIR/results-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$RESULTS_DIR"

    log "Stopping tcpdump..."
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no ubuntu@"$PUBLIC_IP" \
        "sudo kill \$(cat /opt/quiet-room/pcaps/tcpdump.pid) 2>/dev/null; sleep 2" 2>/dev/null

    log "Extracting JA3 fingerprints..."
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no ubuntu@"$PUBLIC_IP" "bash -s" <<'EXTRACT'
set -e
cd /opt/quiet-room

# Extract JA3 from PCAP via tshark
PCAP=$(ls -t pcaps/*.pcap | head -1)
echo "PCAP: $PCAP ($(du -h "$PCAP" | cut -f1))"

sudo tshark -r "$PCAP" -Y "tls.handshake.type == 1" \
    -T fields -e frame.time -e ip.src -e tls.handshake.ja3 -e tls.handshake.ja3_full \
    -E separator="|" 2>/dev/null > /tmp/ja3-extract.txt

echo "ClientHellos captured: $(wc -l < /tmp/ja3-extract.txt)"
echo ""
echo "=== Unique JA3 fingerprints ==="
awk -F'|' '{print $3}' /tmp/ja3-extract.txt | sort | uniq -c | sort -rn
echo ""
echo "=== JA3 by source IP ==="
awk -F'|' '{print $2, $3}' /tmp/ja3-extract.txt | sort | uniq -c | sort -rn | head -30
echo ""
echo "=== JA3 with time ranges ==="
awk -F'|' '
!seen[$3]++ { first[$3]=$1; src[$3]=$2 }
{ last[$3]=$1; count[$3]++ }
END {
    for (j in first) printf "%4d  %-16s  %s...%s  %s\n", count[j], src[j], substr(j,1,16), substr(j,length(j)-7), first[j]
}' /tmp/ja3-extract.txt | sort -k3

# Try JA4 extraction if pyja4 is available
echo ""
echo "=== JA4 extraction ==="
if /opt/quiet-room/venv/bin/python3 -c "import ja4" 2>/dev/null; then
    /opt/quiet-room/venv/bin/python3 -c "
from ja4 import JA4
import subprocess, json

pcap = '$(ls -t pcaps/*.pcap | head -1)'
# Use tshark JSON output for JA4 computation
result = subprocess.run(
    ['tshark', '-r', pcap, '-Y', 'tls.handshake.type == 1', '-T', 'json',
     '-e', 'frame.time', '-e', 'ip.src', '-e', 'tls.handshake.type',
     '-e', 'tls.handshake.version', '-e', 'tls.handshake.ciphersuite',
     '-e', 'tls.handshake.extensions.supported_version',
     '-e', 'tls.handshake.extension.type',
     '-e', 'tls.handshake.sig_hash_alg'],
    capture_output=True, text=True)
print('JA4 extraction attempted — check results files')
" 2>/dev/null || echo "pyja4 import failed, using JA3 only"
else
    echo "pyja4 not available, using JA3 fingerprints only"
    echo "JA4 can be computed offline from the PCAP using: ja4 -r pcap_file"
fi

# Copy canary log
echo ""
echo "=== Canary triggers ==="
if [ -f logs/canary.ndjson ]; then
    wc -l logs/canary.ndjson
    python3 -c "
import json
types={}
with open('logs/canary.ndjson') as f:
    for line in f:
        r=json.loads(line)
        t=r['canary_type']
        types[t]=types.get(t,0)+1
for k,v in sorted(types.items(), key=lambda x:-x[1]):
    print(f'  {v:3d}  {k}')
" 2>/dev/null || true
else
    echo "No canary triggers yet"
fi
EXTRACT

    log "Downloading results..."
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no ubuntu@"$PUBLIC_IP":/tmp/ja3-extract.txt "$RESULTS_DIR/" 2>/dev/null
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no ubuntu@"$PUBLIC_IP":/opt/quiet-room/pcaps/*.pcap "$RESULTS_DIR/" 2>/dev/null
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no ubuntu@"$PUBLIC_IP":/opt/quiet-room/logs/*.ndjson "$RESULTS_DIR/" 2>/dev/null || true
    cp "$STATE_DIR/scan-log.txt" "$RESULTS_DIR/" 2>/dev/null || true

    log "Results saved to: $RESULTS_DIR"
    log "  PCAP: $RESULTS_DIR/*.pcap"
    log "  JA3:  $RESULTS_DIR/ja3-extract.txt"
    log "  Logs: $RESULTS_DIR/*.ndjson"
    log ""
    log "Next: analyze results, then ./aws-deploy.sh destroy"
}

destroy() {
    log "Tearing down AWS resources..."

    if [ -f "$STATE_DIR/instance-id" ]; then
        INSTANCE_ID=$(cat "$STATE_DIR/instance-id")
        log "Terminating instance $INSTANCE_ID..."
        $AWS ec2 terminate-instances --region "$REGION" --instance-ids "$INSTANCE_ID" > /dev/null 2>&1
        $AWS ec2 wait instance-terminated --region "$REGION" --instance-ids "$INSTANCE_ID" 2>&1
        log "  Instance terminated."
    fi

    if [ -f "$STATE_DIR/sg-id" ]; then
        SG_ID=$(cat "$STATE_DIR/sg-id")
        log "Deleting security group $SG_ID..."
        sleep 5  # Wait for ENI detachment
        $AWS ec2 delete-security-group --region "$REGION" --group-id "$SG_ID" 2>&1 || true
        log "  SG deleted."
    fi

    rm -f "$STATE_DIR/instance-id" "$STATE_DIR/sg-id" "$STATE_DIR/public-ip" "$STATE_DIR/domain"
    log "Cleanup complete. Results preserved in $STATE_DIR/results-*"
}

case "${1:-help}" in
    deploy)  deploy ;;
    scan)    scan ;;
    collect) collect ;;
    destroy) destroy ;;
    *)
        echo "Usage: $0 {deploy|scan|collect|destroy}"
        echo ""
        echo "  deploy   — launch EC2 + honeypot + tcpdump"
        echo "  scan     — run automated scans + print URLs for LLM agents"
        echo "  collect  — download PCAPs, extract JA3/JA4, get canary logs"
        echo "  destroy  — terminate instance, delete SG"
        ;;
esac
