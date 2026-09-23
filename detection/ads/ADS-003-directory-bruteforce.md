# ADS-003: Directory Brute-Force Detection

## 1. Goal

Detect directory brute-force and content discovery tools (dirb, dirsearch, gobuster, ffuf, feroxbuster, wpscan) by combining JA4 TLS fingerprints, high request rates, 404 response patterns, and robots_bait canary triggers.

## 2. Categorization

- **MITRE ATT&CK**: [T1595.003 — Active Scanning: Wordlist Scanning](https://attack.mitre.org/techniques/T1595/003/)
- **Kill Chain Phase**: Reconnaissance

## 3. Strategy Abstract

Directory brute-force tools share a distinctive operational pattern: hundreds to thousands of HTTP requests in rapid succession, high 404 response rates, and robots_bait canary triggers. Detection uses three layers:

1. **JA4 fingerprint matching** — identifies the specific tool or TLS library
2. **Request rate + 404 ratio** — behavioral signal that catches unknown tools
3. **robots_bait canary** — catches any tool that reads and probes robots.txt disallowed paths

**Data sources**: Zeek `ssl.log` + `http.log`, or Suricata TLS + HTTP events, honeypot canary logs, web server access logs.

## 4. Technical Context

### Directory Scanner Fingerprints

| Tool | cipher_hash | ext_hash | Cipher Count | ALPN | TLS Library | Sessions |
|------|------------|----------|-------------|------|-------------|----------|
| dirb | `e8f1e7e78f70` | `b26ce05bbdd6` | 31 | h2 | libcurl/OpenSSL | 37 |
| dirsearch | `ab0a1bf427ad` | `ecd0401ec68b` | 17 | h1 | Python ssl | 12,308 |
| gobuster | `f57a46bbacb6` | `ab7e3b40a677` | 13 | none | Go crypto/tls | 33 |
| ffuf | `9dc949149365` | `e5728521abd4` | 19 | none | Go crypto/tls | 31 |
| feroxbuster | `1d37bd780c83` | `8e6e362c5eac` | 30 | h2 | Rust/OpenSSL | 279 |
| wpscan | `1d37bd780c83` | `8537cf56674e` | 30 | h2 | Ruby/OpenSSL | 5 |
| nikto | `1d37bd780c83` | `ecd0401ec68b` | 30 | none | Perl/OpenSSL | 8,340 |

### Shared cipher_hash Groups

Several tools share the same cipher_hash because they link to the same underlying TLS library:

| cipher_hash | Tools | Library | Disambiguation |
|-------------|-------|---------|----------------|
| `1d37bd780c83` | feroxbuster, wpscan, nikto, curl | OpenSSL 3.x | ext_hash differs per tool |
| `ab0a1bf427ad` | dirsearch, Python requests | Python ssl module | ext_hash + ALPN |
| `f57a46bbacb6` | gobuster, Go WebFetch | Go crypto/tls (modern) | Behavioral/canary |

### Canary Trigger Profile

| Tool | robots_bait | css_hidden | aria_link | link_prefetch | Total |
|------|------------|-----------|-----------|---------------|-------|
| dirsearch | 411 | yes | — | yes | 411+ |
| feroxbuster | 252 | yes | yes | yes | 252+ |
| zap | 172 | yes | yes | yes | 172+ |
| nikto | 112 | yes | — | yes | 112+ |
| katana | 52 | yes | yes | — | 52+ |
| dirb | 21 | — | — | — | 21 |
| ffuf | 18 | — | — | — | 18 |
| gobuster | 12 | — | — | — | 12 |

robots_bait is the highest-volume canary (591 total triggers) and the most reliable indicator for directory brute-force tools.

## 5. Blind Spots and Assumptions

- **Assumption**: HTTP request/response logging is available to measure 404 rates. Without HTTP logs, detection relies solely on JA4 + canary.
- **Blind spot**: Tools using custom wordlists that don't overlap with robots.txt bait paths won't trigger robots_bait.
- **Blind spot**: Slow, rate-limited directory scanning (e.g., 1 request/second) may fall below request rate thresholds. Compensate with longer aggregation windows.
- **Blind spot**: gobuster and ffuf share Go crypto/tls cipher_hash with legitimate Go services. Behavioral correlation is essential.

## 6. False Positives

- **Web crawlers**: Legitimate crawlers (Googlebot, Bingbot) may trigger robots_bait if poorly behaved. Check User-Agent and reverse DNS.
- **API clients**: High-volume Go or Python API clients may match cipher_hash. Correlate with 404 rate — API clients should have near-zero 404s.
- **CI/CD health checks**: Automated tests hitting multiple endpoints. Usually from known internal IPs with consistent User-Agent.

**Expected false positive rate**: Low when combining JA4 + request rate + 404 ratio. Medium for JA4-only detection.

## 7. Validation

```bash
# dirb (37 sessions, 21 robots_bait triggers)
docker run --rm --network harness-net dirb https://172.30.0.2:8443/ /wordlists/common.txt -S

# dirsearch (12,308 sessions, 411 robots_bait)
docker run --rm --network harness-net dirsearch -u https://172.30.0.2:8443 --no-color -t 5

# gobuster (33 sessions, 12 robots_bait)
docker run --rm --network harness-net gobuster dir -u https://172.30.0.2:8443 -w /wordlists/common.txt -k -q

# ffuf (31 sessions, 18 robots_bait)
docker run --rm --network harness-net ffuf -u https://172.30.0.2:8443/FUZZ -w /wordlists/common.txt -mc all -s

# feroxbuster (279 sessions, 252 robots_bait)
docker run --rm --network harness-net feroxbuster -u https://172.30.0.2:8443 -w /wordlists/common.txt -k -q -t 5 --time-limit 60s
```

## 8. Priority

**P2 — High**

Directory brute-force is a standard early-stage reconnaissance technique. While less immediately dangerous than vulnerability scanning (ADS-002), it often precedes exploitation. The combination of JA4 + request rate + robots_bait canary provides high-confidence detection.

## 9. Response

### SIGMA Rule — Known Directory Scanner Fingerprint

```yaml
title: Directory Brute-Force Tool — JA4 Fingerprint
id: e5f8g004-d4c0-4f93-ae7f-003-dirbrute
status: experimental
description: >
  Detects JA4 fingerprints matching known directory brute-force tools
  (dirb, dirsearch, gobuster, ffuf, feroxbuster).
author: Quiet Room Honeypot Research
date: 2026/09/23
logsource:
  category: network_connection
  product: zeek
  service: ssl
detection:
  selection_dirb:
    ja4_c: 'e8f1e7e78f70'
  selection_ffuf:
    ja4_c: '9dc949149365'
  selection_dirsearch:
    ja4_c: 'ab0a1bf427ad'
    ja4|endswith: '_ecd0401ec68b'
  selection_feroxbuster:
    ja4_c: '1d37bd780c83'
    ja4|endswith: '_8e6e362c5eac'
  selection_wpscan:
    ja4_c: '1d37bd780c83'
    ja4|endswith: '_8537cf56674e'
  condition: 1 of selection_*
falsepositives:
  - Python automation scripts (dirsearch cipher_hash)
  - curl/OpenSSL tools (feroxbuster cipher_hash — check ext_hash)
  - Authorized security scanners
level: high
tags:
  - attack.reconnaissance
  - attack.t1595.003
```

### SIGMA Rule — Behavioral (Request Rate + 404s)

```yaml
title: Directory Brute-Force — High 404 Rate
id: e5f8g005-d4c0-4f93-ae7f-003-dirbrute-behav
status: experimental
description: >
  Detects a single source IP generating a high rate of HTTP 404 responses,
  indicating directory/file brute-force activity.
author: Quiet Room Honeypot Research
date: 2026/09/23
logsource:
  category: web
  product: zeek
  service: http
detection:
  selection:
    response_code: 404
  timeframe: 5m
  condition: selection | count() by src_ip > 50
falsepositives:
  - Broken sitemaps causing bulk 404s
  - Misconfigured API clients
level: medium
tags:
  - attack.reconnaissance
  - attack.t1595.003
```

### Splunk SPL

```spl
index=zeek sourcetype=zeek:ssl
| eval ja4_cipher=mvindex(split(ja4, "_"), 1),
       ja4_ext=mvindex(split(ja4, "_"), 2)
| eval scanner=case(
    ja4_cipher="e8f1e7e78f70", "dirb",
    ja4_cipher="9dc949149365", "ffuf",
    ja4_cipher="ab0a1bf427ad" AND ja4_ext="ecd0401ec68b", "dirsearch",
    ja4_cipher="1d37bd780c83" AND ja4_ext="8e6e362c5eac", "feroxbuster",
    ja4_cipher="1d37bd780c83" AND ja4_ext="8537cf56674e", "wpscan",
    true(), null()
  )
| where isnotnull(scanner)
| stats count AS sessions
        values(scanner) AS tools
        min(_time) AS first_seen
        max(_time) AS last_seen
  BY src_ip
| sort -sessions
```

**Behavioral — HTTP 404 burst:**

```spl
index=zeek sourcetype=zeek:http
| bin _time span=5m AS window
| stats count AS total_requests
        count(eval(status_code=404)) AS not_found
  BY src_ip, window
| eval ratio_404=round(not_found/total_requests, 2)
| where not_found >= 50 AND ratio_404 >= 0.7
| eval alert="Directory brute-force: ".not_found." 404s (".ratio_404*100."%) in 5m"
```

**Correlation — JA4 + robots_bait canary:**

```spl
index=zeek sourcetype=zeek:ssl
| eval ja4_cipher=mvindex(split(ja4, "_"), 1)
| where ja4_cipher IN ("e8f1e7e78f70", "9dc949149365", "ab0a1bf427ad",
                        "1d37bd780c83")
| stats count AS tls_sessions BY src_ip
| join type=left src_ip
  [ search index=honeypot sourcetype=canary_trigger canary_type="robots_bait"
    | stats count AS robots_triggers BY src_ip ]
| where isnotnull(robots_triggers)
| eval confidence=case(
    robots_triggers >= 50, "critical",
    robots_triggers >= 10, "high",
    robots_triggers >= 1, "medium"
  )
| table src_ip, tls_sessions, robots_triggers, confidence
```

### Elastic KQL

```kql
tls.client.ja4_c: ("e8f1e7e78f70" or "9dc949149365")
  or (tls.client.ja4_c: "ab0a1bf427ad" and tls.client.ja4: *_ecd0401ec68b)
  or (tls.client.ja4_c: "1d37bd780c83" and tls.client.ja4: (*_8e6e362c5eac or *_8537cf56674e))
```

**Behavioral — 404 burst (ES|QL):**

```esql
FROM zeek-http-*
| WHERE @timestamp > NOW() - 5 MINUTES
| STATS total = COUNT(*),
        not_found = SUM(CASE(http.response.status_code == 404, 1, 0)),
        unique_paths = COUNT_DISTINCT(url.path)
  BY source.ip
| EVAL ratio_404 = not_found / total
| WHERE not_found >= 50 AND ratio_404 >= 0.7
| SORT not_found DESC
```
