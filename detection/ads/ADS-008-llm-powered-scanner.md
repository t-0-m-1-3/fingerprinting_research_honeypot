# ADS-008: LLM-Powered Scanner Detection

## 1. Goal

Detect LLM-powered penetration testing tools (hackingBuddyGPT, strix, rogue, pentest-swarm-ai, xalgorix) that use large language models to drive reconnaissance and vulnerability discovery. These tools produce standard HTTP library TLS fingerprints but exhibit distinctive behavioral patterns caused by LLM inference latency.

## 2. Categorization

- **MITRE ATT&CK**: [T1595.002 — Active Scanning: Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/), [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- **Kill Chain Phase**: Reconnaissance, Weaponization
- **Priority**: P2 High (emerging threat class)

## 3. Strategy Abstract

LLM-powered scanners inherit their HTTP library's TLS fingerprint — they cannot be identified by JA4 alone. Detection relies on **behavioral analysis**: unusually low request rates with long inter-request intervals (10-60s, caused by LLM inference), targeted/adaptive path selection, and semantic response analysis patterns.

**Data sources**: JA4 from Zeek `ssl.log` or Arkime, HTTP request logs, canary events, request timing analysis.

**Key insight**: Traditional scanners send hundreds of requests per minute using wordlists. LLM scanners send 1-5 requests per minute, with each request informed by the LLM's analysis of previous responses. The timing gap between requests is the primary detection signal.

## 4. Technical Context

### 4.1 TLS Fingerprints (Inherited, Not Unique)

| Tool | HTTP Library | JA4 | Cipher Hash | Shared With |
|------|-------------|-----|-------------|-------------|
| hackingBuddyGPT | Python httpx | `t13i1712h1_ab0a1bf427ad_ecd0401ec68b` | `ab0a1bf427ad` | dirsearch |
| strix | Python requests | `t13i1712h1_ab0a1bf427ad_8537cf56674e` | `ab0a1bf427ad` | rogue, wpscan |
| rogue | Python requests + Chromium | `t13i1712h1_ab0a1bf427ad_8537cf56674e` | `ab0a1bf427ad` | strix, wpscan |
| pentest-swarm-ai | Go crypto/tls | *(pending — Go fingerprint not yet captured)* | *(pending)* | nuclei/gobuster family |

All share cipher_hash `ab0a1bf427ad` (Python ssl module) — the most common bot fingerprint on the internet. **TLS fingerprinting alone cannot distinguish LLM scanners from traditional Python scanners.**

### 4.2 httpx vs requests Disambiguation

Python httpx and requests are distinguishable by JA4 ext_hash:

| Library | Ext Hash | Tools Using |
|---------|----------|------------|
| httpx | `ecd0401ec68b` | hackingBuddyGPT, dirsearch |
| requests | `8537cf56674e` | strix, rogue, wpscan |

### 4.3 Behavioral Comparison

| Metric | Traditional Scanner | LLM Scanner |
|--------|-------------------|-------------|
| Requests/minute | 100-10,000+ | 1-5 |
| Inter-request interval | <100ms | 10-60s |
| Path selection | Sequential wordlist | Targeted, context-dependent |
| Response handling | Pattern/regex matching | Semantic analysis |
| Adaptivity | Fixed scan plan | Adapts based on responses |
| Session duration | 30s-10min | 5-30min |
| Unique paths/session | 100-10,000+ | 10-50 |

### 4.4 Dual-Fingerprint Signal

Tools like rogue and xalgorix use both a Python/Go HTTP client AND a headless browser (Playwright/Chromium), producing **two distinct JA4 fingerprints from one source IP**:

1. Python requests: `ab0a1bf427ad` (cipher_hash)
2. Chromium BoringSSL: `8daaf6152771` (cipher_hash)

No legitimate browser-based application also makes raw Python HTTP requests from the same IP. Seeing both fingerprints is a strong indicator.

## 5. Blind Spots and Assumptions

### Assumptions
- LLM inference takes >5s per turn, creating observable inter-request delays
- LLM tools use standard HTTP libraries without TLS fingerprint randomization
- Request volume is low enough that rate-based thresholds are meaningful

### Blind Spots
- **Fast inference** (GPU-accelerated or cloud API with low latency) reduces inter-request intervals, potentially below the detection threshold
- **Batched requests**: Some LLM tools may generate multiple requests per inference turn, briefly mimicking traditional scanner burst patterns
- **Hybrid tools**: Tools that combine LLM decision-making with traditional wordlist scanning may not exhibit pure LLM timing patterns
- **Proxy/CDN fronting**: If an LLM scanner routes through a CDN, the TLS fingerprint belongs to the CDN, not the tool

## 6. False Positives

| Source | Mitigation |
|--------|-----------|
| Manual pentester using curl/httpx interactively | Similar timing pattern. Correlate with canary triggers and path diversity. Manual testers rarely trigger robots_bait or css_hidden canaries. |
| API integration tests (low rate, Python) | Typically hit known endpoints repeatedly, not exploratory paths. Check for novel path discovery. |
| Monitoring/health checks | Fixed paths, fixed intervals (exact periodicity). LLM scanners have variable intervals. |
| Web crawlers (Googlebot, etc.) | Different JA4 fingerprints (Java/C++ TLS), different User-Agent, respect robots.txt |

## 7. Validation

### Test Procedure
1. Run hackingBuddyGPT against the honeypot with Ollama (llama3.2:3b)
2. Verify: request rate <5/min, inter-request interval >10s
3. Verify: canary triggers (robots_bait, css_hidden expected)
4. Verify: Python ssl cipher_hash `ab0a1bf427ad` present
5. Run dirsearch against the same honeypot and compare timing patterns

### Expected Results
- hackingBuddyGPT: 1-3 req/min, 20-60s intervals, <50 unique paths
- dirsearch: 500+ req/min, <10ms intervals, 10,000+ unique paths
- Both share cipher_hash `ab0a1bf427ad` — only timing distinguishes them

## 8. Detection Queries

### SIGMA Rule

```yaml
title: LLM-Powered Scanner - Low Rate Python SSL with Adaptive Paths
id: a8b9c0d1-e2f3-4567-8901-234567890abc
status: experimental
description: >
  Detects potential LLM-powered scanning tools by identifying Python SSL
  TLS fingerprints with unusually low request rates and long inter-request
  intervals characteristic of LLM inference delays.
references:
  - https://github.com/ipa-lab/hackingBuddyGPT
  - https://github.com/strix-ai/strix
logsource:
  product: zeek
  service: ssl
detection:
  ja4_python:
    ja4_c: 'ab0a1bf427ad'    # Python ssl cipher_hash
  condition: ja4_python
  # Note: SIGMA alone cannot express timing/rate conditions.
  # Use platform-specific rate analysis in Splunk/Elastic queries below.
fields:
  - id.orig_h
  - ja4
  - server_name
level: medium
tags:
  - attack.reconnaissance
  - attack.t1595.002
```

### Splunk SPL

```spl
| Detect LLM-powered scanners: Python SSL fingerprint + low request rate

index=zeek sourcetype=zeek:ssl ja4_c="ab0a1bf427ad"
| bucket _time span=5m
| stats count AS requests
        dc(server_name) AS unique_hosts
        range(_time) AS session_duration
        values(ja4) AS ja4_values
        BY id_orig_h, _time
| where requests < 25 AND requests > 2
| eval avg_interval = if(requests > 1, session_duration / (requests - 1), 0)
| where avg_interval > 10
| eval ja4_count = mvcount(ja4_values)
| eval dual_fingerprint = if(ja4_count > 1, "yes", "no")
| table _time, id_orig_h, requests, avg_interval, unique_hosts, dual_fingerprint, ja4_values
| sort - avg_interval
```

### Splunk SPL (Dual-Fingerprint Detection)

```spl
| Detect dual-fingerprint tools (Python + Chromium from same IP)

index=zeek sourcetype=zeek:ssl
| stats dc(ja4_c) AS unique_cipher_hashes
        values(ja4_c) AS cipher_hashes
        count AS total_sessions
        BY id_orig_h
| where unique_cipher_hashes >= 2
| where match(cipher_hashes, "ab0a1bf427ad") AND match(cipher_hashes, "8daaf6152771")
| table id_orig_h, total_sessions, cipher_hashes
```

### Elastic KQL

```kql
// Python SSL clients with low request volume (pre-filter)
zeek.ssl.ja4_c: "ab0a1bf427ad"

// Then aggregate in Elasticsearch:
// POST zeek-ssl-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        { "term": { "zeek.ssl.ja4_c": "ab0a1bf427ad" } },
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ]
    }
  },
  "aggs": {
    "by_source": {
      "terms": { "field": "source.ip", "size": 100 },
      "aggs": {
        "request_count": { "value_count": { "field": "@timestamp" } },
        "time_range": {
          "stats": { "field": "@timestamp" }
        },
        "unique_ja4": {
          "cardinality": { "field": "zeek.ssl.ja4" }
        }
      }
    }
  }
}
// Post-filter: sources with request_count < 25 in 5min window
// and (max_time - min_time) / (request_count - 1) > 10000ms
```

### Arkime / Security Onion

```
// Python SSL fingerprint with session analysis
tls.ja4_c == ab0a1bf427ad && protocols == tls

// Then in session list:
// Sort by packets ascending — LLM scanners have few sessions
// Check inter-session timing in timeline view
// Flag if avg gap > 10s between sessions from same source
```

## 9. Response

| Confidence | Action |
|-----------|--------|
| Low (Python SSL only) | Log and tag for analyst review |
| Medium (Python SSL + low rate + long intervals) | Enrich with canary data. If canary triggered, escalate to High. |
| High (Medium + canary trigger OR dual fingerprint) | Block source IP at WAF. Alert SOC. Capture full session for analysis. |

### Enrichment Steps
1. Correlate source IP with canary trigger log — did this IP trigger robots_bait, css_hidden, or comment_cred?
2. Check for dual fingerprint (Python + Chromium from same IP)
3. Review request paths — are they exploratory (novel paths) or repetitive (monitoring)?
4. Check if inter-request intervals have high variance (LLM) vs fixed periodicity (cron/monitor)
