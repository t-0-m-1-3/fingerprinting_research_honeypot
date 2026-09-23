# ADS-001: TLS Cipher Enumeration Detection

## 1. Goal

Detect hosts performing TLS cipher suite enumeration — sending many distinct TLS ClientHello messages with different cipher suite configurations to a single target in a short time window. This is the primary behavior of nmap `ssl-enum-ciphers`, testssl.sh, sslscan, and sslyze.

## 2. Categorization

- **MITRE ATT&CK**: [T1046 — Network Service Scanning](https://attack.mitre.org/techniques/T1046/), [T1595.002 — Active Scanning: Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/)
- **Kill Chain Phase**: Reconnaissance

## 3. Strategy Abstract

This detection counts the number of distinct JA4 fingerprints originating from a single source IP within a sliding time window. Legitimate clients produce 1-3 JA4 values (e.g., HTTP/1.1 + HTTP/2 ALPN variants). Cipher enumeration tools produce 10-400+ distinct JA4 values in seconds.

**Data sources**: Zeek `ssl.log` or Suricata TLS events with JA4 extraction enabled.

**Enrichment**: After detecting a burst, correlate with:
1. Known scanner cipher_hash values (see Section 4)
2. Canary token triggers from the same source IP (see ADS-005)
3. Deprecated protocol probes from the same source (see ADS-007)

**Thresholds**:
- **P1**: ≥10 unique JA4 from one source IP in 60 seconds → cipher enumeration
- **P2**: ≥5 unique JA4 from one source IP in 60 seconds → probable scanner activity

## 4. Technical Context

### Tools and JA4 Diversity

From harness testing (2026-09-23) and earlier scans:

| Tool | Unique JA4s per Scan | Total Sessions | cipher_hash | Behavior |
|------|---------------------|----------------|-------------|----------|
| nmap ssl-enum-ciphers | 55+ | 90 | `8f28d1f76561` (primary) | Probes SSLv3→TLS1.3 in rapid burst |
| testssl.sh | 94 | 122 | `778603501f98` (primary) | Probes all versions + individual ciphers |
| sslscan | 20 | 93 | `a9850205cb0f` | Probes TLS 1.0→1.3 cipher sets |
| sslyze | 411 | 447 | `0c65036c8509` | 2-cipher probes, one per supported cipher |
| Coordinated scanner (AWS) | 6+ per IP | 87 (5 IPs) | `ea0618708e31` | Randomized extensions, stable cipher_hash |

### Key Distinguishing Features

- **nmap**: 71-cipher primary probe (`8f28d1f76561`), then SSLv3 probes (`ts3*`), TLS 1.0 probes (`t10*`)
- **testssl.sh**: Starts with 9-cipher minimal probe (`778603501f98`), iterates through protocol versions
- **sslscan**: 28-cipher TLS 1.0 probes (`a9850205cb0f`), moves to TLS 1.2/1.3
- **sslyze**: 2-cipher probes (`0c65036c8509`) — tests one cipher at a time, generating hundreds of unique JA4s

### Wild Scanner Correlation

The coordinated nmap-style scanner observed on AWS (5 IPs, 87 sessions) used JA3 randomization (randomized TLS extension ordering) to evade JA3-based detection. JA4's sorted hashing partially defeated this — cipher_hash `ea0618708e31` was consistent across the coordinated scan.

## 5. Blind Spots and Assumptions

- **Assumption**: JA4 extraction is enabled on the TLS termination point. Without JA4, fall back to counting distinct JA3 hashes or raw cipher suite lists.
- **Blind spot**: If the attacker rate-limits their probes (e.g., 1 probe per minute over hours), the burst threshold won't trigger. Mitigate with a longer aggregation window (24h) at the cost of more false positives.
- **Blind spot**: CDN-terminated TLS hides the original client's fingerprint. This detection only works when you see the raw ClientHello.
- **Blind spot**: A scanner that uses only one cipher set per connection (e.g., always TLS 1.3 with default ciphers) and varies only the extensions won't trigger the JA4 diversity threshold.

## 6. False Positives

- **Load balancers / health checks**: May produce 2-4 distinct JA4 values (different ALPN, connection reuse settings). Threshold of ≥10 avoids this.
- **Browser preconnect + speculative connections**: Chrome pre-connects may vary ALPN, producing 2-3 JA4s. Well below threshold.
- **Internal security scanners**: Authorized testssl.sh or sslscan runs. Allowlist scanner source IPs.
- **TLS library version upgrades**: During a rolling deploy, a fleet may briefly produce 2 different JA4s. Not a burst from one IP.

**Expected false positive rate**: Very low at threshold ≥10. Near zero at threshold ≥20.

## 7. Validation

```bash
# nmap — generates 55+ unique JA4 in <30s
nmap --script ssl-enum-ciphers -p 8443 172.30.0.2

# testssl.sh — generates 94 unique JA4
docker run --rm --network harness-net testssl.sh --quiet --fast 172.30.0.2:8443

# sslscan — generates 20 unique JA4
docker run --rm --network harness-net sslscan --no-colour 172.30.0.2:8443

# sslyze — generates 411 unique JA4
docker run --rm --network harness-net sslyze 172.30.0.2:8443
```

## 8. Priority

**P1 — Critical**

TLS cipher enumeration is an unambiguous indicator of active reconnaissance. The behavioral signal (10+ unique JA4 from one IP) is nearly impossible to produce accidentally. Combined with deprecated protocol detection (ADS-007), this provides high-confidence alerting.

## 9. Response

### SIGMA Rule

```yaml
title: TLS Cipher Enumeration — JA4 Diversity Burst
id: b3c4e002-a1d7-4f89-8b5e-001-cipher-enum
status: experimental
description: >
  Detects a single source IP producing 10+ distinct JA4 fingerprints
  within 60 seconds, indicating TLS cipher suite enumeration.
author: Quiet Room Honeypot Research
date: 2026/09/23
references:
  - https://github.com/palantir/alerting-detection-strategy-framework
logsource:
  category: network_connection
  product: zeek
  service: ssl
detection:
  selection:
    event_type: 'ssl'
  timeframe: 60s
  condition: selection | count(ja4) by src_ip > 10
falsepositives:
  - Authorized security scanners (testssl.sh, sslscan, sslyze)
  - Load balancers with multiple TLS configurations
level: critical
tags:
  - attack.reconnaissance
  - attack.t1046
  - attack.t1595.002
```

### SIGMA Rule — Known Scanner cipher_hash

```yaml
title: Known TLS Cipher Enumeration Tool — JA4 cipher_hash
id: b3c4e003-a1d7-4f89-8b5e-001-cipher-hash
status: experimental
description: >
  Detects JA4 cipher_hash values belonging to known TLS enumeration tools.
author: Quiet Room Honeypot Research
date: 2026/09/23
logsource:
  category: network_connection
  product: zeek
  service: ssl
detection:
  selection_nmap:
    ja4_c: '8f28d1f76561'
  selection_testssl:
    ja4_c: '778603501f98'
  selection_sslscan:
    ja4_c: 'a9850205cb0f'
  selection_sslyze:
    ja4_c: '0c65036c8509'
  selection_nmap_enum:
    ja4_c: 'e7b476f9520b'
  condition: 1 of selection_*
falsepositives:
  - Authorized internal security scanners
level: high
tags:
  - attack.reconnaissance
  - attack.t1046
```

### Splunk SPL

```spl
index=zeek sourcetype=zeek:ssl
| bin _time span=60s AS window
| stats dc(ja4) AS unique_ja4
        count AS total_sessions
        values(ja4) AS ja4_list
        min(_time) AS first_seen
        max(_time) AS last_seen
  BY src_ip, window
| where unique_ja4 >= 10
| eval severity=case(
    unique_ja4 >= 50, "critical",
    unique_ja4 >= 20, "high",
    unique_ja4 >= 10, "medium"
  )
| sort -unique_ja4
```

**Correlation — known scanner cipher_hash:**

```spl
index=zeek sourcetype=zeek:ssl
| eval ja4_cipher=mvindex(split(ja4, "_"), 1)
| where ja4_cipher IN ("8f28d1f76561", "778603501f98", "a9850205cb0f",
                        "0c65036c8509", "e7b476f9520b")
| eval tool=case(
    ja4_cipher="8f28d1f76561", "nmap",
    ja4_cipher="778603501f98", "testssl",
    ja4_cipher="a9850205cb0f", "sslscan",
    ja4_cipher="0c65036c8509", "sslyze",
    ja4_cipher="e7b476f9520b", "nmap-enum-probe"
  )
| stats count AS sessions
        dc(ja4) AS unique_ja4
        values(tool) AS tools
  BY src_ip
| sort -sessions
```

### Elastic KQL

```kql
event.category: "network" and tls.client.ja4_c: (
  "8f28d1f76561" or "778603501f98" or "a9850205cb0f"
  or "0c65036c8509" or "e7b476f9520b"
)
```

**Elastic aggregation (ES|QL) — JA4 diversity burst:**

```esql
FROM zeek-ssl-*
| WHERE @timestamp > NOW() - 1 HOUR
| STATS unique_ja4 = COUNT_DISTINCT(tls.client.ja4),
        sessions = COUNT(*),
        first_seen = MIN(@timestamp),
        last_seen = MAX(@timestamp)
  BY source.ip
| WHERE unique_ja4 >= 10
| SORT unique_ja4 DESC
```
