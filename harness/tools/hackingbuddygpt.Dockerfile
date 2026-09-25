FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates curl build-essential pkg-config && \
    rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/ipa-lab/hackingBuddyGPT.git /opt/hbg
WORKDIR /opt/hbg
RUN pip install --no-cache-dir -e .
ENTRYPOINT ["wintermute"]
