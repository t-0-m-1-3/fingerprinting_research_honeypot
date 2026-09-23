#!/bin/sh
# Run curl-impersonate with a specific browser profile against the target.
# The harness invokes this with different profiles via different containers:
#   curl-impersonate-chrome → curl_chrome116
#   curl-impersonate-firefox → curl_ff117
#
# Usage: run-curl-impersonate.sh <curl_binary> <target_url>
# Falls back to first arg as curl binary if two args provided.

CURL_BIN="${1:-curl_chrome116}"
TARGET="${2:-https://172.30.0.2:8443}"

# If only one arg and it looks like a URL, it's the target
case "$CURL_BIN" in
    https://*|http://*)
        TARGET="$CURL_BIN"
        CURL_BIN="curl_chrome116"
        ;;
esac

PATHS="/ /about /blog /login /robots.txt /api/v1/health /.env"

for path in $PATHS; do
    echo "  $CURL_BIN ${TARGET}${path}"
    "$CURL_BIN" -sk "${TARGET}${path}" -o /dev/null -w "  %{http_code} ${path}\n" 2>/dev/null || true
done

echo "Done: $CURL_BIN visited $(echo $PATHS | wc -w) pages"
