# TLS Fingerprinting Research Honeypot

A honeypot web application and research toolkit for identifying automated scanners, bots, and LLM agents using JA3/JA4 TLS fingerprints and embedded canary tokens.

## Key Findings

**JA4 cipher hashes are stable across environments; JA3 is not.** The same tool produces different JA3 hashes depending on whether SNI is present (e.g. self-signed vs real hostname), but JA4's inner hashes remain constant. This makes JA4 far more reliable for detection rules.

**JA4 distinguishes Go TLS configurations that JA3 cannot.** All Go-based tools (nuclei, gobuster, httpx) share a single JA3 hash, but JA4 reveals different cipher suites -- Claude's WebFetch uses 13 ciphers while nuclei uses 25.

### Fingerprint Database (6 tools + wild scanners)

| Tool | JA4 Cipher Hash | Cipher Count | False Positive Risk |
|------|----------------|--------------|---------------------|
| nmap ssl-enum-ciphers | `8f28d1f76561` | 71 | Very low |
| nuclei / Go default | `b78ed14e2fd0` | 25 | Medium |
| Claude WebFetch | `f57a46bbacb6` | 13 | Medium |
| curl / OpenSSL | `1d37bd780c83` | 30 | Very high |
| Python ssl | `ab0a1bf427ad` | 17 | High |
| wget / GnuTLS | `13e0e9e1c501` | 68 | Medium |

Full results in [FINDINGS.md](FINDINGS.md) and [ja4_fingerprints.json](ja4_fingerprints.json).

## Components

### Honeypot (`honeypot/`)

Flask application masquerading as a corporate WordPress portal. Features:

- **Canary tokens** -- hidden form fields, aria-hidden links, CSS-invisible links, HTML comment fake credentials, tracking pixels, robots.txt bait paths, meta-refresh redirects, srcset/prefetch canaries
- **WordPress-like endpoints** -- `/wp-login.php`, `/wp-admin/`, `/wp-json/`, `/xmlrpc.php`
- **Scanner bait** -- `/.env`, `/.git/config`, `/actuator/`, `/phpmyadmin/`, `/server-status`
- **NDJSON logging** -- every request and canary trigger logged for analysis

nuclei triggered **91% of canaries** (94/103) in baseline testing.

### Suricata Rules (`suricata-ja3-rules.rules`)

7 detection rules (SIDs 9000001-9000007) using Suricata's `ja3.hash` sticky buffer:

- nmap ssl-enum-ciphers (primary + legacy TLS 1.0 probes)
- Go crypto/tls (nuclei, httpx, gobuster)
- Python ssl, wget/GnuTLS, curl/OpenSSL
- Behavioral: TLS cipher enumeration burst (10+ handshakes in 60s)

### AWS Ephemeral Deployment (`aws-deploy.sh`)

4-phase script to spin up a temporary public-facing honeypot on EC2 with Let's Encrypt TLS (via sslip.io) and tcpdump capture. Designed for testing LLM agent browsing tools against a real hostname.

```bash
export HONEYPOT_KEY_NAME="my-key-pair"
./aws-deploy.sh deploy    # Launch EC2 + honeypot + tcpdump
./aws-deploy.sh scan      # Run automated scans + get URLs for LLM testing
./aws-deploy.sh collect   # Download PCAPs, extract JA3/JA4
./aws-deploy.sh destroy   # Terminate instance, delete SG
```

### Kibana Dashboard (`so-dashboard-scanner-detection.ndjson`)

Importable saved objects for a scanner detection dashboard. Filters on `rule.name:"QUIET-ROOM*"` alert data. Works with Security Onion, OpenSearch Dashboards, or any ELK stack running the Suricata rules.

## Quick Start (Local)

```bash
cd honeypot
docker compose up -d --build
```

The honeypot will be available on HTTP `:80` and HTTPS `:443` (self-signed cert auto-generated). Point your scanner tools at it and capture traffic with tcpdump/tshark/Arkime to extract JA3/JA4 fingerprints.

```bash
# Capture TLS ClientHellos
sudo tcpdump -i eth0 -w capture.pcap 'tcp port 443'

# Extract JA3 via tshark
tshark -r capture.pcap -Y "tls.handshake.type == 1" \
  -T fields -e ip.src -e tls.handshake.ja3

# Extract JA4 (requires FoxIO ja4 tool or pyja4)
ja4 -r capture.pcap
```

## Use Cases

- **Defensive security** -- detect red team/pentester/bot scanning via passive TLS fingerprinting
- **LLM agent identification** -- fingerprint AI browsing tools (WebFetch, ChatGPT, Perplexity)
- **Honeypot research** -- measure canary token effectiveness against different scanner classes
- **IDS rule development** -- build and validate Suricata/Zeek detection signatures

## License

MIT
