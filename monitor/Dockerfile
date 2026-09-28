FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump=4.99.3-1 \
    tshark=4.0.17-0+deb12u3 \
    iproute2=6.1.0-3 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /data/capture

CMD ["sleep", "infinity"]
