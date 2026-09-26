# Research Findings
## JA3/JA4 TLS Fingerprint Scanner Detection

**Date:** 2026-09-14
**Environments:**
- Local: Honeypot on isolated network segment, self-signed TLS
- AWS: Ephemeral EC2 instance, Let's Encrypt via sslip.io
**PCAPs:**
- Local: 3.4MB, 430+ TLS ClientHellos
- AWS: 19MB, 298 JA4 entries from 25+ source IPs

---

## 1. JA4 Fingerprint Summary

### 1.1 Controlled Scans (Our Tools)

| Tool | TLS Library | JA4 (local, no SNI) | JA4 (AWS, with SNI) | Cipher Hash | Ext Hash | Sessions |
|------|------------|---------------------|---------------------|-------------|----------|----------|
| curl 8.11.1 | OpenSSL 3.4.1 | `t13i3011h2_1d37bd780c83_882d495ac381` | `t13d3012h2_1d37bd780c83_882d495ac381` | `1d37bd780c83` | `882d495ac381` | 5+12 |
| wget 1.25.0 | GnuTLS 3.8.9 | `t13i681100_13e0e9e1c501_89ab6efea773` | `t13d681200_13e0e9e1c501_89ab6efea773` | `13e0e9e1c501` | `89ab6efea773` | 3+3 |
| Python 3.12 | OpenSSL via ssl | `t13i171000_ab0a1bf427ad_8e6e362c5eac` | `t13d171100_ab0a1bf427ad_8e6e362c5eac` | `ab0a1bf427ad` | `8e6e362c5eac` | 10+5 |
| nmap 7.95 | NSE OpenSSL | `t13i711000_8f28d1f76561_8e6e362c5eac` + 55 probes | *(not run on AWS)* | `8f28d1f76561` | `8e6e362c5eac` | 90 |
| nuclei 3.3.7 | Go crypto/tls | `t13i251000_b78ed14e2fd0_ab7e3b40a677` | *(not run on AWS)* | `b78ed14e2fd0` | `ab7e3b40a677` | 377 |

### 1.2 LLM Agent / Tool Fingerprints

| Agent/Tool | TLS Library | JA4 (harness) | Cipher Hash | Ext Hash | Sessions |
|------------|------------|---------------|-------------|----------|----------|
| Claude WebFetch | Go crypto/tls | `t13d131100_f57a46bbacb6_e5728521abd4` | `f57a46bbacb6` | `e5728521abd4` | 89 (AWS) |
| hackingBuddyGPT | Python httpx | `t13i1712h1_ab0a1bf427ad_ecd0401ec68b` | `ab0a1bf427ad` | `ecd0401ec68b` | 5 |
| strix | Python requests | `t13i1712h1_ab0a1bf427ad_8537cf56674e` | `ab0a1bf427ad` | `8537cf56674e` | 4 |
| rogue | Python requests | `t13i1712h1_ab0a1bf427ad_8537cf56674e` | `ab0a1bf427ad` | `8537cf56674e` | 4 |
| pentest-swarm-ai | Go crypto/tls | `t13i131000_f57a46bbacb6_f50d94e863eb` | `f57a46bbacb6` | `f50d94e863eb` | 5 |
| pentest-swarm-ai | curl/libcurl (fallback) | `t13i3111h2_e8f1e7e78f70_b26ce05bbdd6` | `e8f1e7e78f70` | `b26ce05bbdd6` | 4 |

### 1.3 JA3 Fingerprints (Legacy)

| Tool | JA3 Hash (local) | JA3 Hash (AWS) |
|------|------------------|----------------|
| curl | `0659743d0a8904909448456a6dfa4b06` | `db8a6f4f5df82ccc66d45af0fdd5a432` |
| wget | `0a35e0b374f9077f46115637ab06ae88` | `00fe6f3d4d8c85a0cba0dfa7c6a23cdc` |
| python3 | `d12b36d1ef0d9915f23e2f80fc938d6b` | `f21f8e6c2a3c0c78abd85a0deacdc2c3` |
| nmap | `f334454dc96768f9612d478fd7c91fe3` | — |
| nuclei | `11a384388ad36777e1a2e121495037fe` | — |
| WebFetch | — | `9b7dcdf3f997f1fb7b4409c94cb7ef36` |

## 2. Key Findings

### 2.1 JA4 > JA3: Environment Stability

**The most important finding: JA4's cipher_hash and ext_hash are stable across environments, while JA3 is not.**

| Tool | JA3 local | JA3 AWS | Match? | JA4 cipher_hash | JA4 ext_hash | Match? |
|------|-----------|---------|--------|-----------------|--------------|--------|
| curl | `0659743d` | `db8a6f4f` | **NO** | `1d37bd780c83` | `882d495ac381` | **YES** |
| wget | `0a35e0b3` | `00fe6f3d` | **NO** | `13e0e9e1c501` | `89ab6efea773` | **YES** |
| python | `d12b36d1` | `f21f8e6c` | **NO** | `ab0a1bf427ad` | `8e6e362c5eac` | **YES** |

JA3 changes because it's an MD5 hash of the raw ClientHello field order — adding the SNI extension (ext 0) when connecting to a real hostname changes the hash entirely. JA4 sorts the extensions and ciphers before hashing, making the inner hashes stable regardless of whether SNI is present.

**Implication:** JA3-based detection rules are environment-specific. A rule matching `0659743d` (curl without SNI) won't match the same curl connecting to a real hostname. JA4 inner hashes solve this — `1d37bd780c83` identifies curl's cipher suite regardless of SNI/ALPN context.

### 2.2 JA4 Prefix Encodes Context

The JA4 prefix changes predictably between environments:

| Tool | Local prefix | AWS prefix | Diff |
|------|-------------|------------|------|
| curl | `t13i3011h2` | `t13d3012h2` | `i`→`d` (SNI), ext 11→12 |
| wget | `t13i681100` | `t13d681200` | `i`→`d` (SNI), ext 11→12 |
| python | `t13i171000` | `t13d171100` | `i`→`d` (SNI), ext 10→11 |

The `i`/`d` flag and extension count encode the SNI state. The cipher count and ALPN value remain constant for the same tool.

### 2.3 Go crypto/tls is NOT Monolithic

**JA3 insight:** All Go tools share one JA3 — `11a38438`.
**JA4 insight:** Go tools have **different** JA4 cipher_hashes depending on their Go version and TLS configuration:

| Go Tool | Cipher Count | Cipher Hash | ALPN |
|---------|-------------|-------------|------|
| nuclei (Go 1.23) | 25 | `b78ed14e2fd0` | none |
| WebFetch (Anthropic) | 13 | `f57a46bbacb6` | none |
| Wild Go scanners | 25 | `b78ed14e2fd0` | none |

WebFetch uses a modern minimal cipher suite (13 ciphers — only TLS 1.3 + ECDHE), while nuclei/gobuster use Go's default 25-cipher set including legacy suites. This means **JA4 can distinguish different Go TLS configurations**, something JA3 cannot do.

### 2.4 Fingerprint Groupings by JA4 Cipher Hash

| Cipher Hash | Cipher Count | TLS Library | Tools Sharing |
|-------------|-------------|-------------|---------------|
| `ab0a1bf427ad` | 17 | Python ssl (OpenSSL) | python3, dirsearch, **hackingbuddygpt**, **strix**, **rogue** |
| `8daaf6152771` | 15 | BoringSSL (Chromium) | selenium-chrome, playwright-chromium, puppeteer, curl-impersonate-chrome |
| `1d37bd780c83` | 30 | OpenSSL / libcurl | curl, feroxbuster, wpscan, nikto |
| `b78ed14e2fd0` | 25 | Go crypto/tls (legacy) | nuclei, httpx (Go), katana |
| `5b57614c22b0` | 17 | NSS (Firefox) | selenium-firefox, playwright-firefox, curl-impersonate-firefox |
| `e8f1e7e78f70` | 31 | libcurl/OpenSSL | dirb, pentest-swarm-ai (curl fallback) |
| `f57a46bbacb6` | 13 | Go crypto/tls (modern) | Claude WebFetch, gobuster, **pentest-swarm-ai** |
| `13e0e9e1c501` | 68 | GnuTLS | wget |
| `8f28d1f76561` | 71 | NSE OpenSSL | nmap ssl-enum-ciphers (primary probe) |
| `9dc949149365` | 19 | Go crypto/tls (custom) | ffuf |
| `723694b0fccc` | 29 | Apple TLS | playwright-webkit |
| `1d947a95fc68` | 31 | Java JSSE | ZAP |
| `5177063c590b` | 86 | Python ssl (legacy) | sqlmap |

**Bold** = LLM-powered tools. Note: all LLM tools share cipher_hashes with traditional tools.

### 2.5 Wild Scanner Activity (AWS)

The AWS honeypot caught real-world scanners within **1 minute** of deployment:

**Coordinated nmap-style scanner (5 IPs):**
- 136.124.34.5, 176.119.150.216, 24.199.113.99, 34.96.60.168, 62.210.93.92
- 87 total sessions performing identical cipher enumeration
- **JA3 randomization detected**: Same cipher suites but randomized TLS extension ordering across connections
- JA4 partially defeats this: cipher_hash `ea0618708e31` consistent across the coordinated scan

**Persistent Go scanner (2 IPs):**
- 154.28.229.21 (33 sessions), 45.153.102.164 (16 sessions)
- JA4 cipher_hash `f57a46bbacb6` — same as WebFetch! Demonstrates that cipher_hash alone cannot distinguish legitimate from malicious Go clients.

**Shared scanning framework:**
- Cipher hash `8daaf6152771` appeared across 4 unrelated IPs — likely a shared scanning tool/framework.

## 3. Detection Strategy

### 3.1 JA4-Based Detection (Preferred)

Match on **cipher_hash + ext_hash** for environment-agnostic detection:

| Detection | Cipher Hash | Severity | False Positive Risk |
|-----------|------------|----------|---------------------|
| nmap primary (71 ciphers) | `8f28d1f76561` | HIGH | Very low — no legitimate client offers 71 ciphers |
| SSLv3 probe (prefix `ts3`) | *(any)* | HIGH | Zero — SSLv3 is dead |
| TLS 1.0 probe (prefix `t10`) | *(any)* | MEDIUM | Very low in modern networks |
| nuclei/Go legacy (25 ciphers) | `b78ed14e2fd0` | MEDIUM | Medium — some Go infrastructure tools |
| wget/GnuTLS (68 ciphers) | `13e0e9e1c501` | LOW | Medium — wget is used for legitimate downloads |
| Python ssl (17 ciphers) | `ab0a1bf427ad` | LOW | High — Python is everywhere |
| curl/OpenSSL (30 ciphers) | `1d37bd780c83` | INFO | Very high — curl is ubiquitous |

### 3.2 JA3-Based Detection (Suricata Rules)

7 Suricata rules deployed (SIDs 9000001-9000007). JA3-based rules are **environment-specific** — they only match traffic where the SNI/ALPN state matches the baseline scan. Useful for known paths but not portable.

### 3.3 Behavioral Signals (Complement JA4)

| Signal | Confidence Boost |
|--------|-----------------|
| 10+ unique JA4 from single IP in 60s | **Very high** (cipher enumeration) |
| SSLv3 or TLS 1.0 ClientHello | **Very high** (no legitimate use) |
| 100+ requests in <10s from single IP | **High** (automated scanner) |
| Canary token trigger (robots bait, CSS hidden) | **High** (bot behavior) |
| No cookies, no JS execution | **Medium** (could be API client) |

## 4. Canary Token Effectiveness

### 4.1 Initial Baseline (Local + AWS, 2026-09-14)

103 canary triggers across 6 tools (curl, nmap, nuclei, python3, wget, WebFetch):

| Canary Type | Triggers | Primary Scanner | Detection Mechanism |
|-------------|----------|-----------------|---------------------|
| robots_bait | 64 | nuclei (59) | Scanners follow robots.txt Disallow paths |
| css_hidden | 18 | nuclei | Bots follow `visibility:hidden` links |
| link_prefetch | 11 | nuclei | Bots fetch `rel=prefetch` resources |
| comment_cred | 8 | nuclei | Scanners extract and test credentials from HTML comments |
| pixel | 1 | curl | 1x1 tracking pixel loaded |
| meta_redirect | 1 | nuclei | Followed `<meta http-equiv="refresh">` in `<noscript>` |

nuclei triggered **94 of 103** canaries (91%).

### 4.2 Full Harness Run (Docker, 2026-09-23)

**1,182 canary triggers** across 22 tools, 9 of 10 canary types active:

| Canary Type | Triggers | Tools That Triggered | Top Triggerers |
|-------------|----------|---------------------|----------------|
| robots_bait | 591 | dirb, dirsearch, feroxbuster, ffuf, gobuster, katana, nikto, zap | dirsearch (411), feroxbuster (252), zap (172) |
| css_hidden | 201 | dirsearch, feroxbuster, katana, nikto, zap | Multiple |
| aria_link | 123 | feroxbuster, katana, zap | — |
| link_prefetch | 112 | dirsearch, feroxbuster, nikto, playwright-\*, puppeteer, selenium-\*, zap | Browsers also trigger this |
| pixel | 103 | feroxbuster, playwright-\*, puppeteer, selenium-\*, zap | Browsers also trigger this |
| srcset_canary | 32 | zap | ZAP exclusively |
| meta_redirect | 16 | zap | ZAP exclusively |
| hidden_field | 2 | zap | ZAP exclusively |
| comment_cred | 2 | zap | ZAP exclusively |
| form_action | 0 | *(none)* | Not triggered in any test |

### 4.3 Canary Detection Tiers

Canary tokens are tiered by false positive risk for alerting (see [ADS-005](detection/ads/ADS-005-canary-token-correlation.md)):

| Tier | Priority | Canary Types | FP Risk | Rationale |
|------|----------|-------------|---------|-----------|
| **Tier 1** | P1 Critical | comment_cred, hidden_field, form_action | Zero | Requires credential extraction or form replay — no browser does this |
| **Tier 2** | P1 High | meta_redirect, srcset_canary, robots_bait | Negligible | noscript redirects, srcset parsing, robots.txt Disallow probing |
| **Tier 3** | P2 High | css_hidden, aria_link | Low | Some accessibility tools may trigger |
| **Tier 4** | P3 Medium | pixel, link_prefetch | Moderate | Browsers legitimately load these — correlate with JA4 |

### 4.4 Key Takeaways

- **robots_bait** is the highest-volume canary (50% of all triggers) — every directory scanner triggers it
- **ZAP** is the most canary-aggressive tool: triggered 7 of 9 canary types, and is the **only** tool to trigger srcset_canary, meta_redirect, hidden_field, and comment_cred
- **Headless browsers** (Playwright, Puppeteer, Selenium) trigger only Tier 4 canaries (pixel, link_prefetch) — expected, since they render pages normally
- **form_action** never fired in any test — may need redesign or tools don't auto-submit forms
- Multi-canary correlation (2+ types from one IP) is a high-confidence scanner indicator

## 5. Evasion Techniques

### 5.1 JA3 Randomization (Observed in the Wild)

The coordinated scanner on AWS demonstrated active JA3 randomization: same cipher suites, randomized TLS extension ordering. This defeats JA3 matching (which depends on extension order) but **partially fails against JA4** (which sorts extensions before hashing — the cipher_hash remains stable).

### 5.2 Other Evasion Methods

1. **JA3/JA4 randomization** — Tools like `ja3transport` (Go) or custom TLS clients randomize cipher suites per connection
2. **Browser impersonation** — `utls` (Go) or `curl-impersonate` to mimic Chrome/Firefox/Safari
3. **Headless browsers** — Playwright/Puppeteer/Selenium produce real browser fingerprints
4. **CDN/proxy fronting** — Cloudflare Workers, AWS Lambda terminate TLS with their own fingerprint
5. **TLS library switching** — Using a different HTTP library than the tool's default

### 5.3 Defenses Against Evasion

- **Canary tokens work regardless of fingerprint** — a bot that follows robots.txt bait or invisible links is caught
- **Behavioral analysis** (request rate, path diversity, no cookies/JS) complements fingerprinting
- **JA3 randomization is itself detectable** — legitimate clients have consistent fingerprints; seeing multiple different JA4s from one IP is suspicious
- **JA4 inner hashes partially survive randomization** — cipher_hash stays stable if only extension ordering is randomized

## 6. Suricata Detection Rules

7 Suricata rules (SIDs 9000001-9000007):

| SID | Rule | Severity |
|-----|------|----------|
| 9000001 | nmap ssl-enum-ciphers primary probe (JA3) | high |
| 9000002 | Go crypto/tls — nuclei/httpx/gobuster (JA3) | medium |
| 9000003 | Python ssl module (JA3) | low |
| 9000004 | wget/GnuTLS (JA3) | low |
| 9000005 | curl/OpenSSL (JA3) | info |
| 9000006 | TLS cipher enumeration burst (10+ in 60s) | high |
| 9000007 | nmap legacy TLS 1.0 cipher probe (JA3) | high |

## 7. Artifacts

| File | Description |
|------|-------------|
| `ja4_fingerprints.json` | v2.1 fingerprint database — 33 tools (29 traditional + 4 LLM-powered), JA3 + JA4 from local, AWS, and harness environments |
| `suricata-ja3-rules.rules` | Suricata JA3 rules (SIDs 9000001-9000007) |
| `so-dashboard-scanner-detection.ndjson` | Kibana/OpenSearch saved objects for scanner detection dashboard |
| `aws-deploy.sh` | 4-phase AWS deployment script (deploy/scan/collect/destroy) |
| `honeypot/app.py` | Honeypot Flask application with 10 canary token types |
| `harness/` | Dockerized fingerprinting harness — 22 tools in isolated containers |
| `detection/ads/` | 8 Alerting Detection Strategy documents (Palantir framework) with SIGMA/Splunk/Elastic queries |

## 8. LLM-Powered Pentest Tool Fingerprints

**Date:** 2026-09-25
**Environment:** Docker harness (harness-net, 172.30.0.0/24) with Ollama sidecar (llama3.2:3b)
**PCAP:** `harness/captures/llm-tools-test.pcap` (131KB)

### 8.1 Tools Tested

| Tool | Language | HTTP Library | LLM Provider | Category |
|------|----------|-------------|-------------|----------|
| hackingBuddyGPT | Python 3.13 | httpx | Ollama (local) | cat6-llm-local |
| pentest-swarm-ai | Go | crypto/tls + curl | Ollama (local) | cat6-llm-local |
| strix | Python 3.12 | requests | OpenAI (cloud) | cat7-llm-cloud |
| rogue | Python 3.12 + Playwright | requests + Chromium | OpenAI (cloud) | cat7-llm-cloud |

### 8.2 JA4 Fingerprints

| Tool | JA4 | Cipher Hash | Ext Hash | Shared With |
|------|-----|-------------|----------|-------------|
| hackingBuddyGPT | `t13i1712h1_ab0a1bf427ad_ecd0401ec68b` | `ab0a1bf427ad` | `ecd0401ec68b` | **dirsearch** (both httpx) |
| strix | `t13i1712h1_ab0a1bf427ad_8537cf56674e` | `ab0a1bf427ad` | `8537cf56674e` | **rogue, wpscan** (all requests) |
| rogue | `t13i1712h1_ab0a1bf427ad_8537cf56674e` | `ab0a1bf427ad` | `8537cf56674e` | **strix, wpscan** (all requests) |
| pentest-swarm-ai (Go) | `t13i131000_f57a46bbacb6_f50d94e863eb` | `f57a46bbacb6` | `f50d94e863eb` | **Claude WebFetch, gobuster** (all Go modern) |
| pentest-swarm-ai (curl) | `t13i3111h2_e8f1e7e78f70_b26ce05bbdd6` | `e8f1e7e78f70` | `b26ce05bbdd6` | **dirb** (both curl/libcurl) |

### 8.3 Key Finding: LLM Tools Don't Produce New TLS Fingerprints

**LLM-powered pentest tools inherit their HTTP library's TLS fingerprint.** They do not produce unique ClientHellos — the LLM drives the *logic* (what to scan, what paths to try), but the *network layer* is a standard HTTP library.

This means:
- hackingBuddyGPT is **indistinguishable** from dirsearch by JA4 alone (both httpx)
- strix is **indistinguishable** from rogue or wpscan by JA4 alone (all requests)
- TLS fingerprinting cannot detect "LLM-powered" as a category

### 8.4 httpx vs requests: Distinguishable by JA4

Despite sharing cipher_hash `ab0a1bf427ad` (Python ssl module), httpx and requests produce **different ext_hashes**:

| Library | Ext Hash | Extension Count | ALPN |
|---------|----------|-----------------|------|
| httpx | `ecd0401ec68b` | 12 | h1 |
| requests | `8537cf56674e` | 12 | h1 |

The difference is in the TLS extensions offered. This allows distinguishing httpx-based tools (dirsearch, hackingBuddyGPT) from requests-based tools (strix, rogue, wpscan).

### 8.5 Behavioral Detection: The Only Reliable Signal

Since TLS fingerprints can't identify LLM scanners, **behavioral analysis is the primary detection vector**:

| Signal | Traditional Scanner | LLM Scanner |
|--------|-------------------|-------------|
| Request rate | 100-10,000+ req/min | 1-5 req/min |
| Inter-request interval | <100ms | 10-60s (LLM inference) |
| Path selection | Wordlist brute-force | Targeted, adaptive |
| Response analysis | Pattern matching | Semantic understanding |
| Request sequence | Predictable order | Context-dependent |

**Proposed detection rule:**
```
JA4 cipher_hash == 'ab0a1bf427ad' (Python)
AND requests_per_minute < 5
AND inter_request_interval_avg > 10s
→ MEDIUM confidence: LLM-powered scanner
```

### 8.6 Dual-Fingerprint Tools

Multiple LLM tools produce **two distinct JA4 fingerprints from a single source IP**:

| Tool | Fingerprint 1 | Fingerprint 2 |
|------|---------------|---------------|
| rogue | Python requests (`ab0a1bf427ad`) | Chromium/BoringSSL (expected) |
| pentest-swarm-ai | Go crypto/tls (`f57a46bbacb6`) | curl/libcurl (`e8f1e7e78f70`) |
| xalgorix (pending) | Go crypto/tls (`f57a46bbacb6`) | Chromium/BoringSSL (expected) |

Seeing two different TLS fingerprints from the same IP is a detection signal — no legitimate single application mixes HTTP library stacks.

## 9. Next Steps

- ~~Capture pentest-swarm-ai's Go crypto/tls fingerprint~~ — Done: `f57a46bbacb6` (modern Go, matches WebFetch/gobuster)
- Build and test xalgorix (Go + Chromium dual fingerprint)
- Deploy cloud tools to AWS with per-tool egress filtering via Squid proxy
- Test JA3 randomization tools (ja3transport, utls) to validate evasion detection
- Deploy ADS queries to Security Onion / Splunk and tune thresholds against production traffic
- Build canary trigger dashboard (Grafana or Kibana) for real-time monitoring
- Write ADS-008 for LLM-powered scanner detection (behavioral + TLS combined)

## 10. Alerting Detection Strategies

Eight ADS documents following the [Palantir ADS Framework](https://github.com/palantir/alerting-detection-strategy-framework), each containing SIGMA rules, Splunk SPL, and Elastic KQL queries:

| ADS | Detection | MITRE ATT&CK | Priority | Key Signal |
|-----|-----------|-------------|----------|------------|
| [ADS-001](detection/ads/ADS-001-tls-cipher-enumeration.md) | TLS Cipher Enumeration | T1046, T1595.002 | P1 Critical | 10+ unique JA4 from 1 IP in 60s |
| [ADS-002](detection/ads/ADS-002-vulnerability-scanner.md) | Vulnerability Scanner | T1190, T1595.002 | P1 Critical | cipher_hash `1d947a95fc68` (ZAP), `5177063c590b` (sqlmap) + canary |
| [ADS-003](detection/ads/ADS-003-directory-bruteforce.md) | Directory Brute-Force | T1595.003 | P2 High | Request rate + robots_bait canary + 404 ratio |
| [ADS-004](detection/ads/ADS-004-go-recon-tools.md) | Go Recon Tools | T1595.002, T1046 | P2 High | cipher_hash `b78ed14e2fd0` (legacy Go) + canary correlation |
| [ADS-005](detection/ads/ADS-005-canary-token-correlation.md) | Canary Token Correlation | T1595.002, T1190 | P1-P3 tiered | Canary type determines priority; multi-canary = P1 |
| [ADS-006](detection/ads/ADS-006-browser-impersonation.md) | Browser Impersonation | T1036, T1071.001 | P3 Medium | Browser cipher_hash + non-browser ext_hash mismatch |
| [ADS-007](detection/ads/ADS-007-deprecated-tls-protocol.md) | Deprecated TLS Protocol | T1046, T1595.002 | P1 Critical | JA4 prefix `ts3`/`t10`/`t11` — zero legitimate use |
| [ADS-008](detection/ads/ADS-008-llm-powered-scanner.md) | LLM-Powered Scanner | T1595.002, T1190 | P2 High | Python SSL + low rate + long intervals + canary |

See [`detection/ads/README.md`](detection/ads/README.md) for log field schema and platform field mappings.
