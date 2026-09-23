#!/usr/bin/env python3
"""Honeypot web application for JA3/JA4 TLS fingerprinting research.

A realistic-looking web application designed to attract and fingerprint
scanner tools (nmap, nuclei, httpx, LLM agents). Serves common endpoints
that automated tools probe. All requests logged as NDJSON for correlation
with JA3/JA4 TLS fingerprints captured via tcpdump/tshark/Arkime.

Canary tokens are embedded throughout using accessibility and CSS techniques:
- Hidden form fields (bot honeypot traps)
- aria-hidden links to unique tracking endpoints
- CSS-invisible canary links (visibility:hidden, color:transparent)
- HTML comments with fake credentials
- 1x1 pixel tracking beacons
- robots.txt disallow entries as bait paths

Each canary hit is logged with its type for correlation with TLS fingerprints.
"""

import datetime
import hashlib
import json
import os
import uuid
from pathlib import Path

from flask import Flask, Response, abort, jsonify, redirect, request

app = Flask(__name__)
app.secret_key = os.urandom(32)

LOG_DIR = os.environ.get("QUIET_ROOM_LOG_DIR", "/var/log/quiet-room")
ACCESS_LOG = os.path.join(LOG_DIR, "access.ndjson")
CANARY_LOG = os.path.join(LOG_DIR, "canary.ndjson")

# --------------------------------------------------------------------------- #
# Canary token infrastructure
# --------------------------------------------------------------------------- #

# Each canary has a unique token derived from its type + location.
# When a canary is triggered, we log the token, type, and source page.
# This lets us correlate: "nuclei followed the aria-hidden link on /blog"
# vs "curl only hit the homepage" vs "LLM agent parsed HTML comments".

CANARY_TYPES = {
    "hidden_field": "Bot filled a hidden form field (display:none)",
    "aria_link": "Followed an aria-hidden=true link (invisible to users)",
    "css_hidden": "Followed a visibility:hidden / transparent link",
    "comment_cred": "Used credentials found in HTML comments",
    "pixel": "Loaded a 1x1 tracking pixel beacon",
    "robots_bait": "Probed a path only listed in robots.txt Disallow",
    "meta_redirect": "Followed a meta refresh redirect in noscript",
    "link_prefetch": "Fetched a rel=prefetch resource",
    "srcset_canary": "Fetched an image from srcset attribute",
    "form_action": "Posted to a hidden form action endpoint",
}


def _canary_token(canary_type, page):
    """Generate a deterministic but opaque canary token."""
    raw = f"quiet-room:{canary_type}:{page}:2026"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _log_canary(canary_type, page, extra=None):
    """Log a canary trigger event."""
    entry = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event": "canary_triggered",
        "canary_type": canary_type,
        "canary_desc": CANARY_TYPES.get(canary_type, "unknown"),
        "source_page": page,
        "token": _canary_token(canary_type, page),
        "remote_addr": request.remote_addr,
        "user_agent": request.headers.get("User-Agent", ""),
        "method": request.method,
        "path": request.path,
    }
    if extra:
        entry.update(extra)
    try:
        Path(LOG_DIR).mkdir(parents=True, exist_ok=True)
        with open(CANARY_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Request logging — every request gets logged as NDJSON
# --------------------------------------------------------------------------- #

def _log_request(resp):
    """Log every request/response pair as one NDJSON line."""
    entry = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "method": request.method,
        "path": request.path,
        "query": request.query_string.decode("utf-8", errors="replace"),
        "status": resp.status_code,
        "remote_addr": request.remote_addr,
        "user_agent": request.headers.get("User-Agent", ""),
        "host": request.headers.get("Host", ""),
        "content_type": request.content_type or "",
        "content_length": request.content_length or 0,
        "accept": request.headers.get("Accept", ""),
        "referer": request.headers.get("Referer", ""),
        "x_forwarded_for": request.headers.get("X-Forwarded-For", ""),
        "authorization": "present" if request.headers.get("Authorization") else "",
        "request_id": str(uuid.uuid4()),
    }
    try:
        Path(LOG_DIR).mkdir(parents=True, exist_ok=True)
        with open(ACCESS_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass
    return resp


app.after_request(_log_request)


# --------------------------------------------------------------------------- #
# Canary HTML fragments — injected into pages
# --------------------------------------------------------------------------- #

def _canary_hidden_field(page):
    """Hidden form field trap. Bots auto-fill; humans never see it."""
    tok = _canary_token("hidden_field", page)
    return (
        f'<div style="position:absolute;left:-9999px;top:-9999px;height:0;width:0;overflow:hidden">'
        f'<input type="text" name="website" value="" tabindex="-1" autocomplete="off" '
        f'data-canary="{tok}">'
        f'</div>'
    )


def _canary_aria_links(page):
    """Links invisible to screen readers and sighted users, visible to crawlers."""
    tok = _canary_token("aria_link", page)
    return (
        f'<nav aria-hidden="true" style="position:absolute;width:1px;height:1px;'
        f'overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap">'
        f'<a href="/internal/assets/report-{tok}.pdf">Q3 Report</a>'
        f'<a href="/internal/api/v2/export/{tok}">Data Export</a>'
        f'<a href="/staff/directory/{tok}">Staff Directory</a>'
        f'</nav>'
    )


def _canary_css_hidden(page):
    """Links hidden via CSS — crawlers/scanners often follow regardless."""
    tok = _canary_token("css_hidden", page)
    return (
        f'<div style="visibility:hidden;height:0;overflow:hidden">'
        f'<a href="/backup/db-export-{tok}.sql" style="color:transparent">backup</a>'
        f'<a href="/config/app-settings-{tok}.json" style="color:transparent">config</a>'
        f'</div>'
    )


def _canary_pixel(page):
    """1x1 tracking pixel — loads when page is rendered by any client."""
    tok = _canary_token("pixel", page)
    return (
        f'<img src="/t/{tok}.gif" width="1" height="1" alt="" '
        f'style="position:absolute;left:-1px;top:-1px" loading="eager">'
    )


def _canary_prefetch(page):
    """rel=prefetch link — browsers and some crawlers will prefetch these."""
    tok = _canary_token("link_prefetch", page)
    return f'<link rel="prefetch" href="/assets/font-{tok}.woff2">'


def _canary_srcset(page):
    """srcset canary — some parsers fetch all srcset candidates."""
    tok = _canary_token("srcset_canary", page)
    return (
        f'<img src="/img/logo.png" srcset="/img/logo-{tok}-2x.png 2x, '
        f'/img/logo-{tok}-3x.png 3x" width="1" height="1" alt="" '
        f'style="position:absolute;opacity:0">'
    )


def _canary_meta_redirect(page):
    """noscript meta redirect — JS-unaware scanners may follow this."""
    tok = _canary_token("meta_redirect", page)
    return (
        f'<noscript><meta http-equiv="refresh" content="10;url=/redirect/{tok}"></noscript>'
    )


def _canary_comment_creds():
    """HTML comments with fake credentials. Scanners parse comments."""
    return (
        '<!-- TODO: remove before production deployment\n'
        '     Dev environment credentials:\n'
        '     Admin panel: /admin/dashboard\n'
        '     Username: admin@acme-corp.internal\n'
        '     Password: AcmeAdmin2026!Summer\n'
        '     API key: ak_live_7f3b9c2d8e4a1056f892de37c4b8a910\n'
        '     Database: mysql://dbadmin:Pr0d-DB-2026@db.acme-corp.internal:3306/acmeportal\n'
        '     S3 bucket: s3://acme-backups-prod (AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE)\n'
        '     -->\n'
        '<!-- Debug: session_secret=xK9mP2vL8nQ4wR7j -->'
    )


def _inject_all_canaries(page):
    """Return all canary HTML fragments for a given page."""
    return "\n".join([
        _canary_comment_creds(),
        _canary_hidden_field(page),
        _canary_aria_links(page),
        _canary_css_hidden(page),
        _canary_pixel(page),
        _canary_prefetch(page),
        _canary_srcset(page),
        _canary_meta_redirect(page),
    ])


# --------------------------------------------------------------------------- #
# HTML templates with canary tokens embedded
# --------------------------------------------------------------------------- #

def _page(title, body, page_id):
    """Render a full HTML page with all canary tokens injected."""
    canaries = _inject_all_canaries(page_id)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — Acme Corp</title>
<meta name="generator" content="WordPress 6.4.3">
<meta name="author" content="Acme Corp IT Department">
<link rel="stylesheet" href="/wp-content/themes/flavor/style.css">
<link rel="icon" href="/favicon.ico">
{_canary_prefetch(page_id)}
</head>
<body>
{canaries}
<header>
<h1>Acme Corp Internal Portal</h1>
<nav>
<a href="/">Home</a>
<a href="/about">About</a>
<a href="/blog">Blog</a>
<a href="/careers">Careers</a>
<a href="/contact">Contact</a>
<a href="/login">Login</a>
</nav>
</header>
<main>
{body}
</main>
<footer>
<p>&copy; 2026 Acme Corp. All rights reserved. Powered by WordPress.</p>
<p><small>Internal use only. Unauthorized access is prohibited.</small></p>
</footer>
{_canary_pixel(page_id)}
</body></html>"""


# --------------------------------------------------------------------------- #
# Canary trigger endpoints — these only exist to catch scanners
# --------------------------------------------------------------------------- #

@app.route("/t/<token>.gif")
def canary_pixel_endpoint(token):
    """1x1 tracking pixel — any client that renders HTML will hit this."""
    _log_canary("pixel", _find_canary_page("pixel", token))
    return Response(
        # Minimal valid 1x1 transparent GIF
        b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff"
        b"\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00"
        b"\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;",
        mimetype="image/gif",
        headers={"Cache-Control": "no-store"},
    )


@app.route("/internal/assets/<path:subpath>")
@app.route("/internal/api/<path:subpath>")
@app.route("/staff/directory/<path:subpath>")
def canary_aria_endpoint(subpath=""):
    """aria-hidden link targets — only crawlers/scanners follow these."""
    _log_canary("aria_link", _find_canary_source(subpath))
    abort(403)


@app.route("/backup/<path:subpath>")
@app.route("/config/<path:subpath>")
def canary_css_hidden_endpoint(subpath=""):
    """CSS-hidden link targets."""
    _log_canary("css_hidden", _find_canary_source(subpath))
    abort(403)


@app.route("/assets/<path:subpath>")
def canary_prefetch_endpoint(subpath=""):
    """rel=prefetch targets."""
    _log_canary("link_prefetch", _find_canary_source(subpath))
    abort(404)


@app.route("/img/<path:subpath>")
def canary_srcset_endpoint(subpath=""):
    """srcset canary images."""
    if any(tok_fragment in subpath for tok_fragment in ["-2x.png", "-3x.png"]):
        _log_canary("srcset_canary", _find_canary_source(subpath))
    abort(404)


@app.route("/redirect/<token>")
def canary_meta_redirect_endpoint(token):
    """noscript meta-refresh redirect target."""
    _log_canary("meta_redirect", _find_canary_page("meta_redirect", token))
    return _page("Redirected", "<p>You have been redirected. <a href='/'>Return home</a>.</p>", "redirect")


def _find_canary_page(canary_type, token):
    """Reverse-lookup which page a canary token came from."""
    for page in ["home", "about", "blog", "contact", "careers", "login", "admin"]:
        if _canary_token(canary_type, page) == token:
            return page
    return "unknown"


def _find_canary_source(subpath):
    """Try to identify source page from a canary URL path."""
    for page in ["home", "about", "blog", "contact", "careers", "login", "admin"]:
        for ctype in CANARY_TYPES:
            tok = _canary_token(ctype, page)
            if tok in subpath:
                return page
    return "unknown"


# --------------------------------------------------------------------------- #
# Hidden form submission trap
# --------------------------------------------------------------------------- #

@app.route("/api/v1/subscribe", methods=["POST"])
def canary_form_trap():
    """Catches bots that auto-submit forms with hidden fields filled."""
    honeypot_val = request.form.get("website", "")
    if honeypot_val:
        _log_canary("hidden_field", "form_submit", {"filled_value": honeypot_val})
    return jsonify({"status": "ok", "message": "Subscribed"}), 200


@app.route("/admin/dashboard", methods=["GET", "POST"])
def canary_comment_cred_admin():
    """Catches scanners that extracted creds from HTML comments."""
    auth = request.authorization
    if auth or request.form.get("log") or request.headers.get("Authorization"):
        _log_canary("comment_cred", "admin_dashboard", {
            "auth_user": auth.username if auth else request.form.get("log", ""),
        })
    return _page("Admin Login Required",
                  '<p>Access denied. <a href="/login">Please log in</a>.</p>',
                  "admin"), 403


@app.route("/api/v1/data", methods=["GET", "POST"])
def canary_comment_cred_api():
    """Catches scanners using the fake API key from HTML comments."""
    api_key = request.headers.get("X-API-Key", "") or request.headers.get("Authorization", "")
    if "ak_live_" in api_key or "7f3b9c2d" in api_key:
        _log_canary("comment_cred", "api_key_used", {"key_fragment": api_key[:20]})
    return jsonify({"error": "Invalid API key", "code": 403}), 403


# --------------------------------------------------------------------------- #
# Content pages — all with canary tokens
# --------------------------------------------------------------------------- #

@app.route("/")
def index():
    return _page("Internal Portal", """
<h2>Welcome to the Acme Corp Portal</h2>
<p>This is the internal employee portal for Acme Corporation.
Please <a href="/login">log in</a> to access company resources.</p>
<div class="announcements">
<h3>Announcements</h3>
<ul>
<li><strong>Sep 2026:</strong> New MFA policy effective Oct 1st. Enroll at <a href="/security/mfa-setup">MFA Setup</a>.</li>
<li><strong>Aug 2026:</strong> VPN client updated. Download from <a href="/downloads/vpn-client">IT Downloads</a>.</li>
<li>IT Support: <a href="mailto:support@acme-corp.internal">support@acme-corp.internal</a></li>
</ul>
</div>
<form method="POST" action="/api/v1/subscribe" style="margin-top:20px">
<h3>Newsletter Signup</h3>
<label>Email: <input type="email" name="email" placeholder="you@acme-corp.internal"></label>
""" + _canary_hidden_field("home") + """
<button type="submit">Subscribe</button>
</form>
""", "home")


@app.route("/about")
def about():
    return _page("About Us", """
<h2>About Acme Corp</h2>
<p>Acme Corporation is a leading provider of enterprise solutions, serving over 500
Fortune 1000 companies worldwide. Founded in 2004, we specialize in cloud infrastructure,
security tooling, and developer experience platforms.</p>
<h3>Leadership</h3>
<ul>
<li>Jane Chen — CEO</li>
<li>Michael Torres — CTO</li>
<li>Sarah Kim — CISO</li>
<li>David Patel — VP Engineering</li>
</ul>
<h3>Office Locations</h3>
<p>San Francisco (HQ) · New York · London · Singapore</p>
""", "about")


@app.route("/blog")
def blog():
    return _page("Engineering Blog", """
<h2>Engineering Blog</h2>
<article>
<h3><a href="/blog/q3-security-updates">Q3 2026 Security Updates</a></h3>
<p class="meta">Posted by Sarah Kim, CISO · September 10, 2026</p>
<p>We're rolling out new MFA policies across all internal services. Starting October 1st,
all employees must enroll in hardware key-based authentication...</p>
</article>
<article>
<h3><a href="/blog/api-v2-migration">API v2 Migration Guide</a></h3>
<p class="meta">Posted by David Patel · August 28, 2026</p>
<p>The legacy API (v1) will be deprecated on December 31, 2026.
All integrations should migrate to the v2 endpoint at /api/v2/...</p>
</article>
<article>
<h3><a href="/blog/infrastructure-updates">Infrastructure Modernization</a></h3>
<p class="meta">Posted by Michael Torres, CTO · August 15, 2026</p>
<p>We've completed our migration to Kubernetes. All production services now run on
our internal k8s clusters with full observability...</p>
</article>
""", "blog")


@app.route("/blog/<slug>")
def blog_post(slug):
    return _page("Blog Post", f"""
<h2>{slug.replace('-', ' ').title()}</h2>
<p class="meta">Acme Corp Engineering Blog</p>
<p>This post is only available to authenticated employees.
<a href="/login">Please log in</a> to continue reading.</p>
""", "blog")


@app.route("/careers")
def careers():
    return _page("Careers", """
<h2>Join Our Team</h2>
<p>We're hiring! Check out our open positions:</p>
<ul>
<li><strong>Senior Security Engineer</strong> — San Francisco (Remote OK)</li>
<li><strong>Platform Engineer</strong> — New York</li>
<li><strong>DevOps Lead</strong> — London</li>
<li><strong>Frontend Developer</strong> — Singapore</li>
</ul>
<p>Apply at <a href="/careers/apply">careers portal</a> or email
<a href="mailto:recruiting@acme-corp.internal">recruiting@acme-corp.internal</a>.</p>
""", "careers")


@app.route("/careers/apply")
def careers_apply():
    return _page("Apply", "<p>Applications are handled through our HR portal. Please log in.</p>", "careers")


@app.route("/contact")
def contact():
    return _page("Contact", """
<h2>Contact Us</h2>
<h3>IT Support</h3>
<p>Email: <a href="mailto:support@acme-corp.internal">support@acme-corp.internal</a><br>
Phone: +1 (415) 555-0142<br>
Slack: #it-helpdesk</p>
<h3>Security Team</h3>
<p>Email: <a href="mailto:security@acme-corp.internal">security@acme-corp.internal</a><br>
Report vulnerabilities: <a href="/.well-known/security.txt">security.txt</a></p>
""", "contact")


# --- Login / Auth ---
@app.route("/login")
@app.route("/wp-login.php", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        _log_canary("comment_cred", "login_attempt", {
            "username": request.form.get("log", ""),
        })
        return redirect("/wp-admin/")
    return _page("Login", """
<h2>Employee Login</h2>
<form method="POST" action="/wp-login.php">
<div>
<label>Username: <input type="text" name="log" autocomplete="username"></label>
</div>
<div>
<label>Password: <input type="password" name="pwd" autocomplete="current-password"></label>
</div>
""" + _canary_hidden_field("login") + """
<div><button type="submit">Log In</button></div>
</form>
<p><a href="/wp-login.php?action=lostpassword">Forgot your password?</a></p>
<p><small>Use your Active Directory credentials. Contact IT if locked out.</small></p>
""", "login")


# --- WordPress-like endpoints ---
@app.route("/wp-admin/")
@app.route("/wp-admin/<path:subpath>")
def wp_admin(subpath=""):
    return _page("Dashboard", "<p>You need to <a href='/login'>log in</a> to access the dashboard.</p>", "admin"), 403


@app.route("/wp-content/<path:subpath>")
def wp_content(subpath=""):
    abort(404)


@app.route("/wp-includes/<path:subpath>")
def wp_includes(subpath=""):
    abort(404)


@app.route("/wp-json/wp/v2/users")
@app.route("/wp-json/wp/v2/posts")
@app.route("/wp-json/wp/v2/<path:subpath>")
def wp_api(subpath=""):
    return jsonify({
        "code": "rest_not_logged_in",
        "message": "You are not authenticated.",
        "data": {"status": 401},
    }), 401


@app.route("/xmlrpc.php", methods=["GET", "POST"])
def xmlrpc():
    return Response(
        '<?xml version="1.0"?><methodResponse><fault><value><struct>'
        '<member><name>faultCode</name><value><int>403</int></value></member>'
        '<member><name>faultString</name><value><string>XML-RPC is disabled.</string></value></member>'
        '</struct></value></fault></methodResponse>',
        mimetype="text/xml", status=403)


# --- Scanner bait / common probe targets ---
@app.route("/robots.txt")
def robots():
    return Response(
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Disallow: /wp-admin/\n"
        "Disallow: /api/\n"
        "Disallow: /backup/\n"
        "Disallow: /config/\n"
        "Disallow: /internal/\n"
        "Disallow: /staff/\n"
        "Disallow: /.env\n"
        "Disallow: /.git/\n"
        "Disallow: /debug/\n"
        "Disallow: /downloads/\n"
        "Disallow: /security/\n"
        "Sitemap: /sitemap.xml\n",
        mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap():
    return Response(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        '<url><loc>/</loc><changefreq>daily</changefreq></url>\n'
        '<url><loc>/about</loc><changefreq>monthly</changefreq></url>\n'
        '<url><loc>/blog</loc><changefreq>weekly</changefreq></url>\n'
        '<url><loc>/careers</loc><changefreq>weekly</changefreq></url>\n'
        '<url><loc>/contact</loc><changefreq>monthly</changefreq></url>\n'
        '</urlset>',
        mimetype="application/xml")


@app.route("/.env")
def dotenv():
    """Scanners always check for .env — return a realistic-looking one."""
    _log_canary("robots_bait", ".env")
    return Response(
        "# Acme Corp Portal — DO NOT COMMIT\n"
        "APP_ENV=production\n"
        "APP_DEBUG=false\n"
        "APP_KEY=base64:xK9mP2vL8nQ4wR7jF5tY3hU6gB0dC1eA=\n"
        "DB_HOST=db.acme-corp.internal\n"
        "DB_DATABASE=acmeportal\n"
        "DB_USERNAME=dbadmin\n"
        "DB_PASSWORD=Pr0d-DB-2026\n"
        "REDIS_HOST=redis.acme-corp.internal\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "MAIL_HOST=smtp.acme-corp.internal\n"
        "MAIL_PASSWORD=mailrelay-2026!\n",
        mimetype="text/plain", status=200)


@app.route("/.git/config")
def git_config():
    _log_canary("robots_bait", ".git/config")
    return Response(
        "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
        "[remote \"origin\"]\n\turl = git@gitlab.acme-corp.internal:engineering/portal.git\n"
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        "[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n",
        mimetype="text/plain", status=200)


@app.route("/.git/HEAD")
def git_head():
    _log_canary("robots_bait", ".git/HEAD")
    return Response("ref: refs/heads/main\n", mimetype="text/plain")


@app.route("/debug/")
@app.route("/debug/<path:subpath>")
@app.route("/downloads/<path:subpath>")
@app.route("/security/<path:subpath>")
def robots_bait_paths(subpath=""):
    """Paths only listed in robots.txt Disallow — only scanners visit these."""
    _log_canary("robots_bait", request.path)
    abort(403)


@app.route("/server-status")
@app.route("/server-info")
def server_status():
    _log_canary("robots_bait", request.path)
    abort(403)


@app.route("/.well-known/security.txt")
@app.route("/security.txt")
def security_txt():
    return Response(
        "Contact: security@acme-corp.internal\n"
        "Preferred-Languages: en\n"
        "Canonical: /.well-known/security.txt\n"
        "Policy: /security-policy\n"
        "Expires: 2027-01-01T00:00:00.000Z\n",
        mimetype="text/plain")


@app.route("/favicon.ico")
def favicon():
    abort(404)


# --- API endpoints ---
@app.route("/api/v1/health")
def api_health():
    return jsonify({"status": "ok", "version": "2.4.1", "uptime": 86400})


@app.route("/api/v1/users")
@app.route("/api/v1/users/<path:subpath>")
def api_users(subpath=""):
    auth = request.headers.get("Authorization", "")
    if not auth:
        return jsonify({"error": "Authentication required", "code": 401}), 401
    if "ak_live_" in auth:
        _log_canary("comment_cred", "api_users", {"auth_header": auth[:30]})
    return jsonify({"error": "Invalid token", "code": 403}), 403


@app.route("/api/v1/config")
def api_config():
    return jsonify({"error": "Forbidden", "code": 403}), 403


@app.route("/api/v1/debug")
@app.route("/api/v1/debug/<path:subpath>")
def api_debug(subpath=""):
    _log_canary("robots_bait", "/api/v1/debug")
    abort(404)


@app.route("/api/v2/<path:subpath>")
def api_v2(subpath=""):
    """v2 API mentioned in blog post — only scanners that parsed content would find it."""
    return jsonify({"error": "API v2 requires authentication", "code": 401, "docs": "/api/v2/docs"}), 401


# --- Admin panels ---
@app.route("/admin/")
@app.route("/admin/<path:subpath>")
@app.route("/administrator/")
@app.route("/phpmyadmin/")
@app.route("/phpMyAdmin/")
@app.route("/pma/")
def admin_panels(subpath=""):
    return _page("Administration",
                  "<p>Access denied. <a href='/login'>Log in</a> with admin credentials.</p>",
                  "admin"), 403


# --- Common CMS/framework probe paths ---
@app.route("/wp-config.php.bak")
@app.route("/backup.sql")
@app.route("/database.sql")
@app.route("/dump.sql")
def sensitive_files():
    _log_canary("robots_bait", request.path)
    abort(403)


@app.route("/actuator/health")
def actuator_health():
    return jsonify({"status": "UP"})


@app.route("/actuator/env")
@app.route("/actuator/beans")
@app.route("/actuator/<path:subpath>")
def actuator_restricted(subpath=""):
    _log_canary("robots_bait", request.path)
    abort(403)


@app.route("/.DS_Store")
@app.route("/Thumbs.db")
@app.route("/web.config")
@app.route("/crossdomain.xml")
def misc_files():
    abort(404)


# --- Catch-all ---
@app.route("/<path:path>")
def catch_all(path):
    abort(404)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import ssl

    host = os.environ.get("QUIET_ROOM_HOST", "0.0.0.0")
    https_port = int(os.environ.get("QUIET_ROOM_HTTPS_PORT", "8443"))
    cert_dir = os.environ.get("QUIET_ROOM_CERT_DIR", "/opt/quiet-room/certs")

    cert_file = os.path.join(cert_dir, "server.crt")
    key_file = os.path.join(cert_dir, "server.key")

    if os.path.exists(cert_file) and os.path.exists(key_file):
        print(f"Starting HTTPS on {host}:{https_port}")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        app.run(host=host, port=https_port, ssl_context=context, threaded=True)
    else:
        print(f"No TLS certs at {cert_dir}")
        print("Generate: openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes")
