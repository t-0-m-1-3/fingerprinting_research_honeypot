FROM ghcr.io/zaproxy/zaproxy:stable
# ZAP baseline scan runs in API mode, no persistent state needed.
# The harness invokes: zap-baseline.py -t <target_url> -I
# -I = don't return failure codes for warnings (we only care about TLS fingerprint)
ENTRYPOINT ["zap-baseline.py"]
