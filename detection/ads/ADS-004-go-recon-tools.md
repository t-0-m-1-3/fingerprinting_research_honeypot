# ADS-004: Go-Based Recon Tool Detection

## 1. Goal

Detect Go-based reconnaissance and scanning tools (httpx, katana, nuclei, gobuster, ffuf) by identifying the Go crypto/tls fingerprint family and correlating with behavioral signals. Go security tools share TLS library characteristics that distinguish them from Go application services.

## 2. Categorization

- **MITRE ATT&CK**: [T1595.002 — Active Scanning: Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/), [T1046 — Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
- **Kill Chain Phase**: Reconnaissance

## 3. Strategy Abstract

Go crypto/tls produces recognizable JA4 fingerprints, but not all Go clients are malicious. This detection distinguishes between:

1. **Legacy Go TLS config** (cipher_hash `b78ed14e2fd0`, 25 ciphers) — used by ProjectDiscovery tools (nuclei, httpx, katana) and older Go security tools. Higher suspicion.
2. **Modern Go TLS config** (cipher_hash `f57a46bbacb6`, 13 ciphers) — used by gobuster, newer Go services, and legitimate infrastructure (including Claude WebFetch). Lower suspicion — requires behavioral correlation.

**Data sources**: Zeek `ssl.log` with JA4, HTTP logs, canary events.

**Key insight**: cipher_hash alone cannot convict a Go client. Correlate with: (a) canary triggers, (b) request volume/diversity, (c) absence of ALPN (h2), (d) known-bad ext_hash values.

## 4. Technical Context

### Go Tool Fingerprints

| Tool | cipher_hash | ext_hash | Cipher Count | ALPN | Sessions | Category |
|------|------------|----------|-------------|------|----------|----------|
| httpx | `b78ed14e2fd0` | `f50d94e863eb` | 25 | none | 2 | Legacy Go |
| katana | `b78ed14e2fd0` | `f50d94e863eb` | 25 | none | 80 | Legacy Go |
| nuclei | `b78ed14e2fd0` | `ab7e3b40a677` | 25 | none | 377 | Legacy Go |
| gobuster | `f57a46bbacb6` | `ab7e3b40a677` | 13 | none | 33 | Modern Go |
| ffuf | `9dc949149365` | `e5728521abd4` | 19 | none | 31 | Custom Go |
| WebFetch (Claude) | `f57a46bbacb6` | `e5728521abd4` | 13 | none | 89 | Modern Go |
| Wild Go scanner | `f57a46bbacb6` | `e5728521abd4` | 13 | none | 50 | Modern Go |

### Two Go cipher_hash Families

**Legacy Go (`b78ed14e2fd0`, 25 ciphers)**:
- Includes legacy cipher suites: TLS_RSA_*, TLS_ECDHE_RSA_WITH_3DES
- Used by tools built with Go ≤1.23 default TLS config
- Higher detection confidence — modern Go services typically use newer Go versions

**Modern Go (`f57a46bbacb6`, 13 ciphers)**:
- Only TLS 1.3 + ECDHE cipher suites — no legacy
- Used by Go ≥1.24+ default config or explicitly configured modern TLS
- Shared with legitimate Go infrastructure (WebFetch, API gateways)
- Lower detection confidence — must correlate with behavior

**Custom Go (`9dc949149365`, 19 ciphers) — ffuf**:
- ffuf uses a custom TLS configuration adding intermediate ciphers
- Unique cipher_hash — high-confidence fingerprint match

### Canary Correlation

| Tool | robots_bait | css_hidden | aria_link | link_prefetch |
|------|------------|-----------|-----------|---------------|
| katana | 52 | yes | yes | — |
| gobuster | 12 | — | — | — |
| ffuf | 18 | — | — | — |
| nuclei* | 59 | — | — | — |

*nuclei from earlier local scans; not in harness run.

### ALPN Absence

All Go recon tools tested use **no ALPN** (`00` in JA4 prefix). This is notable because:
- Browsers always negotiate h2 (or h3)
- curl defaults to h2 with OpenSSL
- A TLS 1.3 client with no ALPN is unusual in web traffic

## 5. Blind Spots and Assumptions

- **Assumption**: The monitored server terminates TLS directly (not behind a CDN/reverse proxy).
- **Blind spot**: Go services behind a load balancer that adds ALPN would lose this signal.
- **Blind spot**: Modern Go cipher_hash (`f57a46bbacb6`) is shared with legitimate Go services — JA4 alone produces false positives. Behavioral correlation is required.
- **Blind spot**: Tools compiled with custom Go TLS configs or using utls for impersonation will have different fingerprints.

## 6. False Positives

| Signal | FP Source | Mitigation |
|--------|-----------|------------|
| Legacy Go cipher_hash | Go microservices on older Go versions | Rare in modern deployments; check src_ip against known infra |
| Modern Go cipher_hash | Any Go HTTP client, API gateways, webhooks | Must combine with canary/behavioral signals |
| No ALPN | Some API clients, IoT devices | Correlate with request patterns |

**Expected false positive rate**: Low for legacy Go (`b78ed14e2fd0`), high for modern Go (`f57a46bbacb6`) without behavioral correlation.

## 7. Validation

```bash
# httpx — Go legacy cipher_hash
echo 'https://172.30.0.2:8443' | docker run --rm -i --network harness-net httpx -silent -follow-redirects -tls-grab

# katana — Go legacy cipher_hash + canary triggers
docker run --rm --network harness-net katana -u https://172.30.0.2:8443 -silent -depth 2 -jc

# gobuster — Go modern cipher_hash
docker run --rm --network harness-net gobuster dir -u https://172.30.0.2:8443 -w /wordlists/common.txt -k -q

# ffuf — custom Go cipher_hash
docker run --rm --network harness-net ffuf -u https://172.30.0.2:8443/FUZZ -w /wordlists/common.txt -mc all -s
```

## 8. Priority

**P2 — High**

Go recon tools (especially nuclei and katana) are commonly used in both authorized pentests and unauthorized reconnaissance. The legacy Go cipher_hash provides medium-confidence detection; correlation with canary triggers or high request volume raises confidence to high.

## 9. Response

### SIGMA Rule — Legacy Go Recon

```yaml
title: Go-Based Recon Tool — Legacy TLS Configuration
id: f6g9h005-e5d1-4fa4-bf80-004-go-recon
status: experimental
description: >
  Detects Go crypto/tls clients using the legacy 25-cipher configuration
  (cipher_hash b78ed14e2fd0), associated with ProjectDiscovery tools
  (nuclei, httpx, katana) and other Go security scanners.
author: Quiet Room Honeypot Research
date: 2026/09/23
logsource:
  category: network_connection
  product: zeek
  service: ssl
detection:
  selection:
    ja4_c: 'b78ed14e2fd0'
  condition: selection
falsepositives:
  - Go microservices built with Go ≤1.23
  - Authorized penetration testing tools
level: high
tags:
  - attack.reconnaissance
  - attack.t1595.002
  - attack.t1046
```

### SIGMA Rule — ffuf Specific

```yaml
title: ffuf Directory Fuzzer — JA4 Fingerprint
id: f6g9h006-e5d1-4fa4-bf80-004-ffuf
status: experimental
description: >
  Detects ffuf's unique JA4 cipher_hash (9dc949149365, 19 ciphers).
  ffuf uses a custom Go TLS config distinct from other Go tools.
author: Quiet Room Honeypot Research
date: 2026/09/23
logsource:
  category: network_connection
  product: zeek
  service: ssl
detection:
  selection:
    ja4_c: '9dc949149365'
  condition: selection
falsepositives:
  - Unlikely — unique cipher configuration
level: high
tags:
  - attack.reconnaissance
  - attack.t1595.003
```

### Splunk SPL

```spl
index=zeek sourcetype=zeek:ssl
| eval ja4_cipher=mvindex(split(ja4, "_"), 1),
       ja4_ext=mvindex(split(ja4, "_"), 2)
| eval go_tool=case(
    ja4_cipher="b78ed14e2fd0" AND ja4_ext="f50d94e863eb", "httpx/katana",
    ja4_cipher="b78ed14e2fd0" AND ja4_ext="ab7e3b40a677", "nuclei",
    ja4_cipher="b78ed14e2fd0", "unknown_go_legacy",
    ja4_cipher="9dc949149365", "ffuf",
    ja4_cipher="f57a46bbacb6" AND ja4_ext="ab7e3b40a677", "gobuster",
    true(), null()
  )
| where isnotnull(go_tool)
| stats count AS sessions
        values(go_tool) AS tools
        dc(ja4) AS unique_ja4
        min(_time) AS first_seen
        max(_time) AS last_seen
  BY src_ip
| sort -sessions
```

**Correlation — Go tool + canary:**

```spl
index=zeek sourcetype=zeek:ssl
| eval ja4_cipher=mvindex(split(ja4, "_"), 1)
| where ja4_cipher IN ("b78ed14e2fd0", "9dc949149365", "f57a46bbacb6")
| stats count AS tls_sessions BY src_ip
| join type=left src_ip
  [ search index=honeypot sourcetype=canary_trigger
    | stats dc(canary_type) AS canary_types
            count AS canary_triggers
      BY src_ip ]
| where isnotnull(canary_triggers) AND canary_triggers > 0
| eval confidence=case(
    canary_types >= 2, "high",
    canary_triggers >= 10, "high",
    canary_triggers >= 1, "medium"
  )
| table src_ip, tls_sessions, canary_types, canary_triggers, confidence
```

### Elastic KQL

**Legacy Go recon tools (high confidence):**

```kql
tls.client.ja4_c: ("b78ed14e2fd0" or "9dc949149365")
```

**All Go clients including modern (requires behavioral correlation):**

```kql
tls.client.ja4_c: ("b78ed14e2fd0" or "9dc949149365" or "f57a46bbacb6")
  and not source.ip: (10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16)
```

**ES|QL aggregation:**

```esql
FROM zeek-ssl-*
| WHERE tls.client.ja4_c IN ("b78ed14e2fd0", "9dc949149365")
| STATS sessions = COUNT(*),
        unique_ja4 = COUNT_DISTINCT(tls.client.ja4),
        first_seen = MIN(@timestamp),
        last_seen = MAX(@timestamp)
  BY source.ip, tls.client.ja4_c
| SORT sessions DESC
```
