# Alerting Detection Strategies

Detection strategies for TLS-fingerprinted scanner activity, following the [Palantir ADS Framework](https://github.com/palantir/alerting-detection-strategy-framework).

## ADS Index

| ID | Name | MITRE ATT&CK | Priority | Key Signal |
|----|------|-------------|----------|------------|
| [ADS-001](ADS-001-tls-cipher-enumeration.md) | TLS Cipher Enumeration | T1046, T1595.002 | P1 Critical | 10+ unique JA4 from 1 IP in 60s |
| [ADS-002](ADS-002-vulnerability-scanner.md) | Vulnerability Scanner Detection | T1190, T1595.002 | P1 Critical | Known vuln scanner cipher_hash + canary |
| [ADS-003](ADS-003-directory-bruteforce.md) | Directory Brute-Force | T1595.003 | P2 High | High request rate + robots_bait canary |
| [ADS-004](ADS-004-go-recon-tools.md) | Go-Based Recon Tools | T1595.002, T1046 | P2 High | Go cipher_hash `b78ed14e2fd0` + canary |
| [ADS-005](ADS-005-canary-token-correlation.md) | Canary Token Correlation | T1595.002, T1190 | P1-P3 tiered | Canary type determines priority |
| [ADS-006](ADS-006-browser-impersonation.md) | Browser Impersonation | T1036, T1071.001 | P3 Medium | Browser cipher_hash + non-browser ext_hash |
| [ADS-007](ADS-007-deprecated-tls-protocol.md) | Deprecated TLS Protocol | T1046, T1595.002 | P1 Critical | JA4 prefix `ts3`/`t10` |

## Log Field Schema

All queries reference these normalized field names. Map to your environment:

| Field | Description | Example |
|-------|-------------|---------|
| `tls.ja4` | Full JA4 string | `t13i3011h2_1d37bd780c83_882d495ac381` |
| `tls.ja4.cipher_hash` | 2nd JA4 component (sorted cipher suites) | `1d37bd780c83` |
| `tls.ja4.ext_hash` | 3rd JA4 component (sorted extensions) | `882d495ac381` |
| `tls.ja4.prefix` | 1st JA4 component (proto+ver+sni+counts+alpn) | `t13i3011h2` |
| `tls.ja3.hash` | JA3 MD5 hash | `0659743d0a8904909448456a6dfa4b06` |
| `tls.version` | Negotiated TLS version | `TLSv1.3` |
| `source.ip` | Client IP address | `172.30.0.10` |
| `destination.ip` | Server IP address | `172.30.0.2` |
| `destination.port` | Server port | `8443` |
| `http.request.uri` | HTTP request path | `/api/v1/health` |
| `http.request.headers.user_agent` | User-Agent header | `Mozilla/5.0` |
| `event.category` | Event classification | `network` |
| `canary.type` | Honeypot canary token type | `robots_bait` |
| `canary.tool` | Tool that triggered the canary | `nikto` |

### Platform Field Mappings

| Normalized Field | Splunk (Zeek/Suricata) | Elastic (ECS) | Security Onion |
|-----------------|----------------------|---------------|----------------|
| `tls.ja4` | `ja4` | `tls.client.ja4` | `rule.ja4` |
| `tls.ja4.cipher_hash` | `ja4_c` | `tls.client.ja4_c` | *(derived)* |
| `tls.ja3.hash` | `ja3` | `tls.client.ja3` | `rule.ja3_hash` |
| `source.ip` | `src_ip` / `id.orig_h` | `source.ip` | `source.ip` |
| `http.request.uri` | `uri` | `url.path` | `http.uri` |

## Data Sources

- **TLS metadata**: Zeek `ssl.log` / Suricata `tls` events with JA3/JA4 enabled
- **HTTP logs**: Zeek `http.log` / Suricata `http` events / web server access logs
- **Canary events**: Honeypot application logs (custom `canary_trigger` events)
- **Enrichment**: Threat intel feeds, ASN/geo lookups, reverse DNS

## Harness Reference Data

Fingerprint database: [`ja4_fingerprints.json`](../../ja4_fingerprints.json)
Canary analysis: 1,182 triggers across 22 tools, 9 active canary types.
Harness run: 2026-09-23, Docker containers on `172.30.0.0/24`.
