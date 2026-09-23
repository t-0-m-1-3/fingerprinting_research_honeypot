# ADS-007: Deprecated TLS Protocol Detection

## 1. Goal

Detect clients sending TLS ClientHello messages using deprecated protocol versions (SSLv3, TLS 1.0, TLS 1.1). No legitimate modern client or browser uses these protocols — their presence indicates cipher enumeration, vulnerability scanning, or severely misconfigured legacy software.

## 2. Categorization

- **MITRE ATT&CK**: [T1046 — Network Service Scanning](https://attack.mitre.org/techniques/T1046/), [T1595.002 — Active Scanning: Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/)
- **Kill Chain Phase**: Reconnaissance

## 3. Strategy Abstract

This detection monitors TLS handshake metadata (JA4 fingerprints or raw ClientHello version fields) for connections advertising SSLv3, TLS 1.0, or TLS 1.1. The JA4 prefix encodes the highest TLS version the client advertises:

| JA4 Prefix | Protocol | Risk |
|-----------|----------|------|
| `ts3*` | SSLv3 | Critical — SSLv3 is universally deprecated since POODLE (2014) |
| `t10*` | TLS 1.0 | High — deprecated since RFC 8996 (March 2021) |
| `t11*` | TLS 1.1 | High — deprecated since RFC 8996 (March 2021) |

**Data sources**: Zeek `ssl.log` with JA4, Suricata TLS events, or raw packet capture with JA4 extraction.

**Enrichment**: Count distinct JA4 fingerprints per source IP within a time window. A single deprecated probe is suspicious; multiple probes across protocol versions confirms cipher enumeration.

## 4. Technical Context

### Tools Observed Using Deprecated Protocols

From harness testing (2026-09-23):

| Tool | JA4 Samples | Protocol | Sessions |
|------|------------|----------|----------|
| testssl.sh | `t00i091100_778603501f98_4178a7550c93` | Mixed (SSLv2→TLS1.3) | 94 unique JA4s |
| sslscan | `t10d280600_a9850205cb0f_195413a0cc0f` | TLS 1.0 | 20 unique JA4s |
| sslyze | `t10d020300_0c65036c8509_18d1e47e0978` | TLS 1.0 | 411 unique JA4s |
| nmap ssl-enum-ciphers | `ts3i640000_e7b476f9520b_000000000000` | SSLv3 | Part of 55+ probe burst |
| nmap ssl-enum-ciphers | `t10i640200_e7b476f9520b_33a13ba74d1c` | TLS 1.0 | Part of 55+ probe burst |

### Key cipher_hash values

- `778603501f98` — testssl.sh (9 ciphers, minimal probe)
- `a9850205cb0f` — sslscan (28 ciphers)
- `0c65036c8509` — sslyze (2 ciphers per probe)
- `e7b476f9520b` — nmap cipher enumeration probes (64 ciphers)

### JA4 Version Encoding

The JA4 version field is positions 2-3 of the prefix:
- `13` = TLS 1.3, `12` = TLS 1.2, `11` = TLS 1.1, `10` = TLS 1.0, `s3` = SSLv3, `00` = unknown/mixed

## 5. Blind Spots and Assumptions

- **Assumption**: The monitored TLS termination point logs JA4 or raw ClientHello version fields. Connections terminated at a CDN/load balancer won't show the original client's TLS version.
- **Blind spot**: TLS 1.2 cipher enumeration probes won't trigger this detection. See ADS-001 for behavioral burst detection.
- **Blind spot**: If the attacker uses a TLS 1.3-only client and only probes TLS 1.3 ciphers, this rule misses them entirely.
- **Edge case**: Some IoT devices or embedded systems may genuinely only support TLS 1.0. If present in your environment, create an allowlist by source IP/subnet.

## 6. False Positives

- **Legacy embedded/IoT devices**: SCADA, POS terminals, or medical devices that haven't been updated. Rate: rare on modern networks, but possible on OT segments.
- **Compliance scanners**: Internal tools like testssl.sh run by your own security team. Mitigate by allowlisting scanner source IPs.
- **TLS health checks**: Monitoring tools that verify deprecated protocols are disabled. Same mitigation.

**Expected false positive rate**: Near zero on modern enterprise networks. Slightly higher on networks with legacy OT/IoT devices.

## 7. Validation

Reproduce with harness tools:

```bash
# SSLv3 probe via nmap
nmap --script ssl-enum-ciphers -p 8443 172.30.0.2

# TLS 1.0 probe via sslscan
docker run --rm --network harness-net sslscan --no-colour 172.30.0.2:8443

# TLS 1.0 probe via sslyze
docker run --rm --network harness-net sslyze 172.30.0.2:8443

# testssl.sh (probes all versions)
docker run --rm --network harness-net testssl.sh --quiet --fast 172.30.0.2:8443

# Manual openssl s_client (TLS 1.0)
openssl s_client -connect 172.30.0.2:8443 -tls1
```

## 8. Priority

**P1 — Critical**

Zero false positives from modern legitimate clients. SSLv3 has been dead since 2014, TLS 1.0/1.1 since RFC 8996 (2021). Any client advertising these versions is either a scanner or dangerously misconfigured. Immediate investigation warranted.

## 9. Response

### SIGMA Rule

```yaml
title: Deprecated TLS Protocol in ClientHello
id: a7d3e001-f8b2-4c91-9a4e-007-deprecated-tls
status: experimental
description: >
  Detects TLS ClientHello advertising SSLv3, TLS 1.0, or TLS 1.1.
  No modern browser or legitimate client uses these protocols.
author: Quiet Room Honeypot Research
date: 2026/09/23
references:
  - https://datatracker.ietf.org/doc/html/rfc8996
  - https://github.com/palantir/alerting-detection-strategy-framework
logsource:
  category: network_connection
  product: zeek
  service: ssl
detection:
  selection_ja4_sslv3:
    ja4|startswith: 'ts3'
  selection_ja4_tls10:
    ja4|startswith: 't10'
  selection_ja4_tls11:
    ja4|startswith: 't11'
  selection_version_field:
    version|contains:
      - 'SSLv3'
      - 'TLSv1.0'
      - 'TLSv1.1'
  condition: 1 of selection_*
falsepositives:
  - Legacy IoT/embedded devices
  - Authorized internal security scanners
level: critical
tags:
  - attack.reconnaissance
  - attack.t1046
  - attack.t1595.002
```

### Splunk SPL

```spl
index=zeek sourcetype=zeek:ssl
| eval ja4_version=substr(ja4, 2, 2)
| where ja4_version IN ("s3", "10", "11")
  OR version IN ("SSLv3", "TLSv1", "TLSv10", "TLSv1.0", "TLSv1.1")
| eval severity=case(
    ja4_version="s3", "critical",
    ja4_version="10", "high",
    ja4_version="11", "high",
    true(), "high"
  )
| stats count AS sessions
        dc(ja4) AS unique_ja4
        values(ja4) AS ja4_list
        values(version) AS tls_versions
        min(_time) AS first_seen
        max(_time) AS last_seen
  BY src_ip, severity
| where sessions > 0
| sort -severity, -sessions
```

**Correlation — multi-protocol enumeration from single source:**

```spl
index=zeek sourcetype=zeek:ssl
| eval ja4_version=substr(ja4, 2, 2)
| stats dc(ja4_version) AS protocol_count
        values(ja4_version) AS protocols
        dc(ja4) AS unique_ja4
        count AS total_sessions
  BY src_ip
| where protocol_count >= 3 AND unique_ja4 >= 5
| eval alert="Multi-protocol TLS enumeration: ".protocols
```

### Elastic KQL

```kql
tls.client.ja4 : (ts3* or t10* or t11*)
  or tls.version : ("SSLv3" or "TLSv1.0" or "TLSv1.1")
```

**Elastic aggregation query (ES|QL):**

```esql
FROM zeek-ssl-*
| WHERE tls.client.ja4 LIKE "ts3*"
    OR tls.client.ja4 LIKE "t10*"
    OR tls.client.ja4 LIKE "t11*"
| STATS sessions = COUNT(*),
        unique_ja4 = COUNT_DISTINCT(tls.client.ja4),
        first_seen = MIN(@timestamp),
        last_seen = MAX(@timestamp)
  BY source.ip
| SORT sessions DESC
```
