FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir flask gunicorn

COPY app.py .

RUN mkdir -p /var/log/quiet-room /opt/quiet-room/certs

ENV QUIET_ROOM_LOG_DIR=/var/log/quiet-room
ENV QUIET_ROOM_CERT_DIR=/opt/quiet-room/certs

EXPOSE 8080 8443

# HTTP by default; mount certs at /opt/quiet-room/certs for HTTPS
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--bind", "0.0.0.0:8443", \
     "--certfile", "/opt/quiet-room/certs/server.crt", \
     "--keyfile", "/opt/quiet-room/certs/server.key", \
     "--access-logfile", "-", "--workers", "2", "app:app"]
