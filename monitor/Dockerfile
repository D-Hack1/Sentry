FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    tshark \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /data/capture

CMD ["sleep", "infinity"]
