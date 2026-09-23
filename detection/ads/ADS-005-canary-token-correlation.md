# ADS-005: Canary Token Correlation

## 1. Goal

Detect automated scanners and bots by correlating canary token triggers with TLS fingerprint and behavioral data. Canary tokens are hidden honeypot elements that no legitimate human user would interact with — triggering them is strong evidence of automated tool activity.

## 2. Categorization

- **MITRE ATT&CK**: [T1595.002 — Active Scanning: Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/), [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- **Kill Chain Phase**: Reconnaissance, Initial Access

## 3. Strategy Abstract

The honeypot embeds 10 canary token types at different levels of the application. Each canary type represents a different automated behavior that legitimate browsers don't exhibit. Detection is tiered by the canary type's false positive risk:

| Tier | Canary Types | FP Risk | Priority |
|------|-------------|---------|----------|
| **Tier 1 — Zero FP** | `comment_cred`, `hidden_field`, `form_action` | None | P1 Critical |
| **Tier 2 — Very Low FP** | `meta_redirect`, `srcset_canary`, `robots_bait` | Negligible | P1 High |
| **Tier 3 — Low FP** | `css_hidden`, `aria_link` | Low | P2 High |
| **Tier 4 — Moderate FP** | `pixel`, `link_prefetch` | Moderate | P3 Medium |

**Data sources**: Honeypot application logs (canary trigger events), correlated with TLS metadata (JA4) and HTTP logs.

**Enrichment**: When a canary fires, look up the source IP's JA4 fingerprint and prior request history. Multiple canary types from one IP dramatically increases confidence.

## 4. Technical Context

### Canary Trigger Data (Harness Run 2026-09-23)

1,182 total canary triggers across 22 tools, 9 active canary types:

| Canary Type | Total Triggers | Tools Triggered | Top Triggerers |
|-------------|---------------|-----------------|----------------|
| `robots_bait` | 591 | dirb, dirsearch, feroxbuster, ffuf, gobuster, katana, nikto, zap | dirsearch (411), feroxbuster (252), zap (172) |
| `css_hidden` | 201 | dirsearch, feroxbuster, katana, nikto, zap | — |
| `aria_link` | 123 | feroxbuster, katana, zap | — |
| `link_prefetch` | 112 | dirsearch, feroxbuster, nikto, playwright-*, puppeteer, selenium-*, zap | Browsers trigger this |
| `pixel` | 103 | feroxbuster, playwright-*, puppeteer, selenium-*, zap | Browsers trigger this |
| `srcset_canary` | 32 | zap | ZAP only |
| `meta_redirect` | 16 | zap | ZAP only |
| `hidden_field` | 2 | zap | ZAP only |
| `comment_cred` | 2 | zap | ZAP only |
| `form_action` | 0 | *(none)* | Not triggered in testing |

### Canary Type Descriptions

| Type | What It Is | Why Bots Trigger It |
|------|-----------|---------------------|
| `robots_bait` | Disallowed path in robots.txt (e.g., `/admin/backup`) | Scanners treat Disallow as a discovery hint |
| `css_hidden` | Link with `visibility:hidden; display:none` CSS | Bots parse HTML but don't render CSS |
| `aria_link` | Link with `aria-hidden="true"` and zero-size styling | Screen readers and bots follow it; users can't see it |
| `link_prefetch` | `<link rel="prefetch">` to a canary URL | Browsers legitimately prefetch; bots also follow |
| `pixel` | 1x1 transparent tracking image | Any client that loads images triggers it |
| `srcset_canary` | Image with `srcset` pointing to canary URL | Only parsers that evaluate srcset trigger it |
| `meta_redirect` | `<meta http-equiv="refresh">` inside `<noscript>` | Bots without JS follow noscript redirects |
| `hidden_field` | Hidden form field with decoy credentials | Only tools that extract and replay form data |
| `comment_cred` | Credentials in HTML comments (`<!-- admin:password -->`) | Scanners extract and test comment credentials |
| `form_action` | Form with action pointing to canary endpoint | Only tools that auto-submit forms |

### Tier Rationale

**Tier 1 (comment_cred, hidden_field, form_action)**: These require the client to parse, extract, and act on hidden data. No browser does this without explicit user action. Zero false positive risk.

**Tier 2 (meta_redirect, srcset_canary, robots_bait)**: `meta_redirect` fires only in `<noscript>` — browsers with JS enabled never follow it. `srcset_canary` requires srcset parsing. `robots_bait` requires reading robots.txt and visiting disallowed paths — ethical crawlers respect Disallow.

**Tier 3 (css_hidden, aria_link)**: Some accessibility tools or browser extensions might follow aria-hidden links. CSS-hidden links are invisible to users but some browser features (reader mode, extensions) could expose them.

**Tier 4 (pixel, link_prefetch)**: Browsers legitimately load pixels and prefetch resources. These canaries are meaningful only when correlated with other signals (non-browser JA4, high request rate).

## 5. Blind Spots and Assumptions

- **Assumption**: The honeypot logs canary triggers with the source IP and timestamp. Without structured canary logs, this detection doesn't work.
- **Blind spot**: Headless browsers (Playwright, Puppeteer, Selenium) trigger Tier 4 canaries legitimately because they render pages. Their canary triggers must be correlated with JA4 to determine if the browser fingerprint matches.
- **Blind spot**: A sophisticated attacker that avoids robots.txt paths, doesn't follow hidden links, and doesn't extract comment credentials won't trigger any canaries.
- **Blind spot**: Canary tokens require the attacker to interact with the honeypot's application layer. Port scanners or TLS-only probes won't trigger canaries.

## 6. False Positives

| Tier | FP Source | Mitigation |
|------|-----------|------------|
| Tier 1 | None expected | — |
| Tier 2 | robots_bait: misbehaving crawlers that ignore Disallow | Check User-Agent; known bots (Googlebot, etc.) may trigger |
| Tier 3 | css_hidden/aria_link: accessibility tools, browser extensions | Verify JA4 — real browsers have known cipher_hash values |
| Tier 4 | pixel/link_prefetch: all browsers | Only alert when combined with non-browser JA4 or other canary types |

## 7. Validation

```bash
# Trigger robots_bait — any directory scanner
docker run --rm --network harness-net dirb https://172.30.0.2:8443/ /wordlists/common.txt

# Trigger css_hidden + aria_link — crawler that follows all links
docker run --rm --network harness-net katana -u https://172.30.0.2:8443 -silent -depth 2

# Trigger comment_cred + hidden_field + meta_redirect — vuln scanner
docker run --rm --network harness-net zap-baseline.py -t https://172.30.0.2:8443 -I

# Trigger pixel + link_prefetch — headless browser
docker run --rm --network harness-net playwright-chromium https://172.30.0.2:8443
```

## 8. Priority

**Tiered: P1 to P3** depending on canary type (see Section 3 table).

- **Tier 1 triggers**: P1 — immediate investigation, likely active exploitation attempt
- **Tier 2 triggers**: P1 — high-confidence automated scanning
- **Tier 3 triggers**: P2 — probable bot activity, verify with JA4 correlation
- **Tier 4 triggers**: P3 — informational unless correlated with other signals

**Multi-canary correlation**: Any source IP triggering 2+ canary types across different tiers escalates to P1 regardless of the individual tier.

## 9. Response

### SIGMA Rule — Tier 1 (Zero FP)

```yaml
title: Honeypot Canary Token — Credential Extraction or Form Replay
id: c5d6e004-b2a8-4e91-8c5f-005-canary-t1
status: experimental
description: >
  Detects Tier 1 canary triggers (comment_cred, hidden_field, form_action)
  which indicate automated credential extraction or form replay. Zero false
  positive rate — no legitimate browser performs these actions.
author: Quiet Room Honeypot Research
date: 2026/09/23
logsource:
  category: application
  product: honeypot
detection:
  selection:
    canary.type:
      - 'comment_cred'
      - 'hidden_field'
      - 'form_action'
  condition: selection
falsepositives: []
level: critical
tags:
  - attack.reconnaissance
  - attack.t1595.002
  - attack.initial_access
  - attack.t1190
```

### SIGMA Rule — Tier 2 (Very Low FP)

```yaml
title: Honeypot Canary Token — Scanner Behavior
id: c5d6e005-b2a8-4e91-8c5f-005-canary-t2
status: experimental
description: >
  Detects Tier 2 canary triggers (meta_redirect, srcset_canary, robots_bait)
  indicating automated scanner activity.
author: Quiet Room Honeypot Research
date: 2026/09/23
logsource:
  category: application
  product: honeypot
detection:
  selection:
    canary.type:
      - 'meta_redirect'
      - 'srcset_canary'
      - 'robots_bait'
  condition: selection
falsepositives:
  - Misbehaving web crawlers ignoring robots.txt Disallow
level: high
tags:
  - attack.reconnaissance
  - attack.t1595.002
```

### SIGMA Rule — Multi-Canary Correlation

```yaml
title: Honeypot Multi-Canary Correlation — Automated Scanner
id: c5d6e006-b2a8-4e91-8c5f-005-canary-multi
status: experimental
description: >
  Detects a single source IP triggering 2+ distinct canary types,
  strongly indicating automated scanner activity.
author: Quiet Room Honeypot Research
date: 2026/09/23
logsource:
  category: application
  product: honeypot
detection:
  selection:
    canary.type|exists: true
  timeframe: 1h
  condition: selection | count(canary.type) by source.ip > 1
falsepositives:
  - Browser triggering pixel + link_prefetch (expected, see Tier 4)
level: high
tags:
  - attack.reconnaissance
  - attack.t1595.002
```

### Splunk SPL

```spl
index=honeypot sourcetype=canary_trigger
| eval tier=case(
    canary_type IN ("comment_cred", "hidden_field", "form_action"), "tier1_critical",
    canary_type IN ("meta_redirect", "srcset_canary", "robots_bait"), "tier2_high",
    canary_type IN ("css_hidden", "aria_link"), "tier3_medium",
    canary_type IN ("pixel", "link_prefetch"), "tier4_info",
    true(), "unknown"
  )
| stats count AS triggers
        dc(canary_type) AS canary_types
        values(canary_type) AS types_triggered
        min(_time) AS first_seen
        max(_time) AS last_seen
  BY src_ip, tier
| eval priority=case(
    tier="tier1_critical", "P1",
    tier="tier2_high", "P1",
    canary_types >= 2, "P1",
    tier="tier3_medium", "P2",
    tier="tier4_info", "P3"
  )
| sort priority, -triggers
```

**Correlation — canary + JA4 enrichment:**

```spl
index=honeypot sourcetype=canary_trigger
| stats dc(canary_type) AS canary_types
        values(canary_type) AS types
        count AS canary_triggers
  BY src_ip
| join type=left src_ip
  [ search index=zeek sourcetype=zeek:ssl
    | stats dc(ja4) AS unique_ja4
            values(ja4) AS ja4_list
            count AS tls_sessions
      BY src_ip ]
| eval risk=case(
    canary_types >= 3 AND unique_ja4 >= 5, "critical",
    canary_types >= 2, "high",
    canary_types >= 1 AND unique_ja4 >= 10, "high",
    canary_triggers >= 10, "medium",
    true(), "low"
  )
| where risk IN ("critical", "high", "medium")
| sort -risk, -canary_triggers
```

### Elastic KQL

**Tier 1 (critical):**

```kql
canary.type: ("comment_cred" or "hidden_field" or "form_action")
```

**Tier 2 (high):**

```kql
canary.type: ("meta_redirect" or "srcset_canary" or "robots_bait")
```

**All canaries with aggregation (ES|QL):**

```esql
FROM honeypot-canary-*
| STATS canary_types = COUNT_DISTINCT(canary.type),
        triggers = COUNT(*),
        types = VALUES(canary.type),
        first_seen = MIN(@timestamp),
        last_seen = MAX(@timestamp)
  BY source.ip
| WHERE canary_types >= 2
| SORT canary_types DESC, triggers DESC
```

**Cross-index correlation — canary + TLS:**

```esql
FROM honeypot-canary-*, zeek-ssl-*
| WHERE source.ip IS NOT NULL
| STATS canary_triggers = COUNT_DISTINCT(canary.type),
        unique_ja4 = COUNT_DISTINCT(tls.client.ja4),
        sessions = COUNT(*)
  BY source.ip
| WHERE canary_triggers >= 1 AND unique_ja4 >= 1
| SORT canary_triggers DESC
```
