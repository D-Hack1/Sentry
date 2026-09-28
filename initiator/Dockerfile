FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    strongswan=5.9.8-5+deb12u5 \
    strongswan-pki=5.9.8-5+deb12u5 \
    libstrongswan-extra-plugins=5.9.8-5+deb12u5 \
    libstrongswan-standard-plugins=5.9.8-5+deb12u5 \
    iproute2=6.1.0-3 \
    iputils-ping=3:20221126-1+deb12u1 \
    iperf3=3.12-1+deb12u2 \
    curl=7.88.1-10+deb12u15 \
    wget=1.21.3-1+deb12u1 \
    ffmpeg=7:5.1.9-0+deb12u1 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/ipsec.d/generated /data/capture

CMD ["sleep", "infinity"]
