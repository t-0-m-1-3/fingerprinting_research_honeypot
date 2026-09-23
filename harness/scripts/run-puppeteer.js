#!/usr/bin/env node
/**
 * Puppeteer browser automation for TLS fingerprinting.
 *
 * Launches headless Chromium, navigates through honeypot pages.
 *
 * Usage: node run-puppeteer.js <target_url>
 */

const puppeteer = require('puppeteer');

const targetUrl = process.argv[2] || 'https://172.30.0.2:8443';

const pages = [
    '/',
    '/about',
    '/blog',
    '/careers',
    '/contact',
    '/login',
    '/robots.txt',
    '/api/v1/health',
    '/wp-json/wp/v2/posts',
];

(async () => {
    const browser = await puppeteer.launch({
        headless: true,
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--ignore-certificate-errors',
        ],
    });

    for (const path of pages) {
        const page = await browser.newPage();
        try {
            await page.goto(`${targetUrl}${path}`, {
                waitUntil: 'networkidle2',
                timeout: 10000,
            });
        } catch (e) {
            console.log(`  ${path}: ${e.message}`);
        } finally {
            await page.close();
        }
    }

    await browser.close();
    console.log(`Visited ${pages.length} pages with Puppeteer/Chromium`);
})();
