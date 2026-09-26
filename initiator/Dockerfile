FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    strongswan \
    strongswan-pki \
    libstrongswan-extra-plugins \
    libstrongswan-standard-plugins \
    iproute2 \
    iputils-ping \
    iperf3 \
    curl \
    wget \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/ipsec.d/generated /data/capture

CMD ["sleep", "infinity"]
