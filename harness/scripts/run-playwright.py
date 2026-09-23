#!/usr/bin/env python3
"""Playwright browser automation for TLS fingerprinting.

Launches a single browser engine, navigates through the honeypot pages,
and clicks links to generate multiple TLS handshakes.

Usage:
    python3 run-playwright.py <target_url> <browser>
    python3 run-playwright.py https://172.30.0.2:8443 chromium
    python3 run-playwright.py https://172.30.0.2:8443 firefox
    python3 run-playwright.py https://172.30.0.2:8443 webkit
"""

import sys
from playwright.sync_api import sync_playwright

target_url = sys.argv[1] if len(sys.argv) > 1 else "https://172.30.0.2:8443"
browser_name = sys.argv[2] if len(sys.argv) > 2 else "chromium"

pages = [
    "/",
    "/about",
    "/blog",
    "/careers",
    "/contact",
    "/login",
    "/robots.txt",
    "/api/v1/health",
    "/wp-json/wp/v2/posts",
]

with sync_playwright() as p:
    launcher = getattr(p, browser_name)
    browser = launcher.launch(headless=True)
    context = browser.new_context(ignore_https_errors=True)

    for path in pages:
        page = context.new_page()
        try:
            page.goto(f"{target_url}{path}", timeout=10000)
            page.wait_for_load_state("networkidle", timeout=5000)
        except Exception as e:
            print(f"  {path}: {e}")
        finally:
            page.close()

    browser.close()

print(f"Visited {len(pages)} pages with {browser_name}")
