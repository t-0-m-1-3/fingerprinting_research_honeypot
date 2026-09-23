FROM lwthiker/curl-impersonate:latest
COPY scripts/run-curl-impersonate.sh /scripts/run-curl-impersonate.sh
RUN chmod +x /scripts/run-curl-impersonate.sh
ENTRYPOINT ["/scripts/run-curl-impersonate.sh"]
