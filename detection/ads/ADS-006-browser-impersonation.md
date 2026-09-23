# ADS-006: Browser Impersonation Detection

## 1. Goal

Detect clients that impersonate real browsers at the TLS layer using tools like curl-impersonate, utls, or custom TLS configurations. These tools match a browser's cipher_hash but produce a different ext_hash, revealing the impersonation through JA4 component mismatch analysis.

## 2. Categorization

- **MITRE ATT&CK**: [T1036 — Masquerading](https://attack.mitre.org/techniques/T1036/), [T1071.001 — Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- **Kill Chain Phase**: Defense Evasion, Command and Control

## 3. Strategy Abstract

Real browsers (Chrome, Firefox, Safari) produce consistent JA4 fingerprints where the cipher_hash and ext_hash are tightly coupled — they come from the same TLS stack. Impersonation tools replicate the cipher suite list (cipher_hash) but often differ in TLS extensions (ext_hash) because:

1. Extensions like `application_settings`, `compressed_certificate`, or `delegated_credentials` are hard to replicate
2. Extension ordering or presence of browser-specific extensions varies
3. The impersonation library may not support all browser extensions

**Detection logic**: When a client presents a **known browser cipher_hash** with an **unknown ext_hash** (not in the baseline of legitimate browser ext_hashes), flag it as potential impersonation.

**Data sources**: Zeek `ssl.log` with JA4 fields, browser fingerprint baseline from harness testing.

## 4. Technical Context

### Browser Fingerprint Baselines

From harness testing (real browser engines via Playwright/Selenium):

**Chromium family (cipher_hash `8daaf6152771`, 15 ciphers, ALPN h2):**

| Client | Full JA4 | ext_hash | Legitimate? |
|--------|---------|----------|-------------|
| Playwright Chromium | `t13i1515h2_8daaf6152771_02713d6af862` | `02713d6af862` | Yes |
| Puppeteer (Chromium) | `t13i1516h2_8daaf6152771_33f857a189cb` | `33f857a189cb` | Yes |
| Puppeteer (alt) | `t13i1516h2_8daaf6152771_61307d0e143d` | `61307d0e143d` | Yes |
| Selenium Chrome | `t13i1516h2_8daaf6152771_0d789d2519e1` | `0d789d2519e1` | Yes |
| curl-impersonate-chrome | `t13i1515h2_8daaf6152771_e5627efa2ab1` | **`e5627efa2ab1`** | **Impersonator** |

**Firefox family (cipher_hash `5b57614c22b0`, 17 ciphers, ALPN h2):**

| Client | Full JA4 | ext_hash | Legitimate? |
|--------|---------|----------|-------------|
| Playwright Firefox | `t13i1714h2_5b57614c22b0_5c2c66f702b0` | `5c2c66f702b0` | Yes |
| Selenium Firefox | `t13i1716h2_5b57614c22b0_3cbfd9057e0d` | `3cbfd9057e0d` | Yes |
| curl-impersonate-firefox | `t13i1713h2_5b57614c22b0_91f45d5059c6` | **`91f45d5059c6`** | **Impersonator** |

**WebKit (cipher_hash `723694b0fccc`, 29 ciphers, ALPN h2):**

| Client | Full JA4 | ext_hash | Legitimate? |
|--------|---------|----------|-------------|
| Playwright WebKit | `t13i2912h2_723694b0fccc_5671b5df5029` | `5671b5df5029` | Yes |

### Impersonation Indicators

**curl-impersonate-chrome** (`e5627efa2ab1`):
- Matches Chrome's cipher_hash `8daaf6152771` perfectly
- ext_hash differs from all legitimate Chromium variants
- Uses BoringSSL but doesn't include Chrome-specific extensions (e.g., `application_settings`, `compressed_certificate`)

**curl-impersonate-firefox** (`91f45d5059c6`):
- Matches Firefox's cipher_hash `5b57614c22b0` perfectly
- ext_hash differs from both Playwright Firefox and Selenium Firefox
- Uses NSS but doesn't include Firefox-specific extension values

### Wild Scanner Correlation

From AWS honeypot data, cipher_hash `8daaf6152771` appeared from multiple scanner IPs:
- 103.196.9.68 → ext_hash `cb7bf5808d99` (not a known browser)
- 185.10.7.38 → ext_hash `e2d80978ab2e` (not a known browser)

These likely use curl-impersonate, utls, or similar Chrome impersonation libraries.

### Extension Count Differences

The JA4 prefix includes extension count, which can also reveal impersonation:

| Client | Prefix ext_count | Notes |
|--------|-----------------|-------|
| Real Chrome (Playwright) | 15 | Baseline |
| Real Chrome (Selenium) | 16 | Slightly different config |
| curl-impersonate-chrome | 15 | Matches Playwright count |
| Real Firefox (Playwright) | 14 | Baseline |
| Real Firefox (Selenium) | 16 | Different config |
| curl-impersonate-firefox | 13 | Lower than real Firefox |

## 5. Blind Spots and Assumptions

- **Assumption**: A baseline of legitimate browser ext_hashes is maintained. New browser versions may produce new ext_hashes that aren't in the baseline — these could be false positives until the baseline is updated.
- **Blind spot**: High-fidelity impersonation tools that replicate all browser extensions (including Chrome-specific ones) will match both cipher_hash and ext_hash, defeating this detection.
- **Blind spot**: This detection only catches impersonation at the TLS layer. If the attacker uses a real headless browser (Playwright/Puppeteer/Selenium) instead of curl-impersonate, the TLS fingerprint is legitimate.
- **Blind spot**: CDN/proxy termination removes the original client's TLS fingerprint.

## 6. False Positives

- **New browser versions**: Chrome/Firefox updates may change ext_hash. Maintain an updated baseline.
- **Electron apps**: Chromium-based desktop apps may have slightly different ext_hashes. They share cipher_hash `8daaf6152771` with different extension configurations.
- **Browser extensions**: Extensions that modify TLS settings could change ext_hash.

**Expected false positive rate**: Low if the browser ext_hash baseline is kept current. Higher during browser major version transitions.

## 7. Validation

```bash
# curl-impersonate-chrome — should match Chrome cipher_hash with wrong ext_hash
docker run --rm --network harness-net curl_chrome110 -sk https://172.30.0.2:8443/ -o /dev/null -w '%{http_code}'

# curl-impersonate-firefox — should match Firefox cipher_hash with wrong ext_hash
docker run --rm --network harness-net curl_ff117 -sk https://172.30.0.2:8443/ -o /dev/null -w '%{http_code}'

# Real Chrome for comparison
docker run --rm --network harness-net selenium-chrome python3 /scripts/run-selenium.py https://172.30.0.2:8443 chrome

# Real Firefox for comparison
docker run --rm --network harness-net playwright-firefox python3 /scripts/run-playwright.py https://172.30.0.2:8443 firefox
```

## 8. Priority

**P3 — Medium**

Browser impersonation is a defense evasion technique, not direct exploitation. It indicates a more sophisticated attacker who is actively trying to avoid TLS-based detection. While the immediate threat level is lower than vulnerability scanning, the intent to evade defenses warrants investigation.

**Escalation to P2**: If a browser-impersonating client also triggers canary tokens (especially Tier 1 or 2 from ADS-005), escalate to P2 — this indicates an attacker using evasion techniques during active scanning.

## 9. Response

### SIGMA Rule

```yaml
title: TLS Browser Impersonation — Mismatched ext_hash
id: g7h0i006-f6e2-4fb5-cg91-006-browser-impersonation
status: experimental
description: >
  Detects clients presenting a known browser cipher_hash (Chrome, Firefox)
  with an ext_hash not matching any known legitimate browser variant.
  Indicates curl-impersonate, utls, or similar impersonation tools.
author: Quiet Room Honeypot Research
date: 2026/09/23
logsource:
  category: network_connection
  product: zeek
  service: ssl
detection:
  # Chrome impersonation: right cipher_hash, wrong ext_hash
  selection_chrome_cipher:
    ja4_c: '8daaf6152771'
  filter_chrome_legit:
    ja4|endswith:
      - '_02713d6af862'  # Playwright Chromium
      - '_33f857a189cb'  # Puppeteer
      - '_61307d0e143d'  # Puppeteer alt
      - '_0d789d2519e1'  # Selenium Chrome
  # Firefox impersonation: right cipher_hash, wrong ext_hash
  selection_firefox_cipher:
    ja4_c: '5b57614c22b0'
  filter_firefox_legit:
    ja4|endswith:
      - '_5c2c66f702b0'  # Playwright Firefox
      - '_3cbfd9057e0d'  # Selenium Firefox
      - '_e6dcd7ae0a9e'  # Selenium Firefox alt
  condition: (selection_chrome_cipher and not filter_chrome_legit)
             or (selection_firefox_cipher and not filter_firefox_legit)
falsepositives:
  - New browser versions with updated ext_hash (update baseline)
  - Electron apps with custom TLS extension configs
level: medium
tags:
  - attack.defense_evasion
  - attack.t1036
  - attack.t1071.001
```

### Splunk SPL

```spl
index=zeek sourcetype=zeek:ssl
| eval ja4_cipher=mvindex(split(ja4, "_"), 1),
       ja4_ext=mvindex(split(ja4, "_"), 2)
| eval browser_family=case(
    ja4_cipher="8daaf6152771", "chrome",
    ja4_cipher="5b57614c22b0", "firefox",
    ja4_cipher="723694b0fccc", "webkit",
    true(), null()
  )
| where isnotnull(browser_family)
| eval legit_chrome=if(ja4_ext IN ("02713d6af862", "33f857a189cb",
                                     "61307d0e143d", "0d789d2519e1"), 1, 0),
       legit_firefox=if(ja4_ext IN ("5c2c66f702b0", "3cbfd9057e0d",
                                      "e6dcd7ae0a9e"), 1, 0),
       legit_webkit=if(ja4_ext="5671b5df5029", 1, 0)
| eval is_legit=case(
    browser_family="chrome", legit_chrome,
    browser_family="firefox", legit_firefox,
    browser_family="webkit", legit_webkit,
    true(), 0
  )
| where is_legit=0
| stats count AS sessions
        values(ja4) AS ja4_list
        values(browser_family) AS impersonated_browser
        min(_time) AS first_seen
        max(_time) AS last_seen
  BY src_ip, ja4_ext
| eval alert="Browser impersonation: ".impersonated_browser." cipher_hash with unknown ext_hash ".ja4_ext
| sort -sessions
```

**Correlation — impersonation + canary:**

```spl
index=zeek sourcetype=zeek:ssl
| eval ja4_cipher=mvindex(split(ja4, "_"), 1),
       ja4_ext=mvindex(split(ja4, "_"), 2)
| where (ja4_cipher="8daaf6152771"
         AND NOT ja4_ext IN ("02713d6af862","33f857a189cb","61307d0e143d","0d789d2519e1"))
    OR (ja4_cipher="5b57614c22b0"
         AND NOT ja4_ext IN ("5c2c66f702b0","3cbfd9057e0d","e6dcd7ae0a9e"))
| stats count AS impersonation_sessions BY src_ip
| join type=left src_ip
  [ search index=honeypot sourcetype=canary_trigger
    | stats count AS canary_triggers, dc(canary_type) AS canary_types BY src_ip ]
| where isnotnull(canary_triggers)
| eval priority=if(canary_types >= 2, "P2-escalated", "P3")
```

### Elastic KQL

```kql
(tls.client.ja4_c: "8daaf6152771"
  and not tls.client.ja4: (*_02713d6af862 or *_33f857a189cb or *_61307d0e143d or *_0d789d2519e1))
or
(tls.client.ja4_c: "5b57614c22b0"
  and not tls.client.ja4: (*_5c2c66f702b0 or *_3cbfd9057e0d or *_e6dcd7ae0a9e))
```

**ES|QL aggregation:**

```esql
FROM zeek-ssl-*
| WHERE tls.client.ja4_c IN ("8daaf6152771", "5b57614c22b0")
| EVAL ja4_parts = SPLIT(tls.client.ja4, "_"),
       ext_hash = MV_INDEX(ja4_parts, 2)
| WHERE NOT ext_hash IN ("02713d6af862", "33f857a189cb", "61307d0e143d",
                          "0d789d2519e1", "5c2c66f702b0", "3cbfd9057e0d",
                          "e6dcd7ae0a9e")
| STATS sessions = COUNT(*),
        first_seen = MIN(@timestamp),
        last_seen = MAX(@timestamp)
  BY source.ip, tls.client.ja4_c, ext_hash
| SORT sessions DESC
```
