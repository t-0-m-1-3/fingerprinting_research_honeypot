#!/usr/bin/env python3
"""Selenium browser automation for TLS fingerprinting.

Usage:
    python3 run-selenium.py <target_url> <browser>
    python3 run-selenium.py https://172.30.0.2:8443 chrome
    python3 run-selenium.py https://172.30.0.2:8443 firefox
"""

import sys
import time

target_url = sys.argv[1] if len(sys.argv) > 1 else "https://172.30.0.2:8443"
browser_name = sys.argv[2] if len(sys.argv) > 2 else "chrome"

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

if browser_name == "chrome":
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--ignore-certificate-errors")
    options.binary_location = "/usr/bin/chromium"

    service = Service("/usr/bin/chromedriver")
    driver = webdriver.Chrome(service=service, options=options)

elif browser_name == "firefox":
    from selenium import webdriver
    from selenium.webdriver.firefox.options import Options
    from selenium.webdriver.firefox.service import Service
    from webdriver_manager.firefox import GeckoDriverManager

    options = Options()
    options.add_argument("--headless")
    options.accept_insecure_certs = True

    service = Service(GeckoDriverManager().install())
    driver = webdriver.Firefox(service=service, options=options)
else:
    print(f"Unknown browser: {browser_name}")
    sys.exit(1)

try:
    for path in pages:
        try:
            driver.get(f"{target_url}{path}")
            time.sleep(0.5)
        except Exception as e:
            print(f"  {path}: {e}")
finally:
    driver.quit()

print(f"Visited {len(pages)} pages with Selenium/{browser_name}")
