FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    strongswan \
    strongswan-pki \
    libstrongswan-extra-plugins \
    libstrongswan-standard-plugins \
    iproute2 \
    iputils-ping \
    iperf3 \
    busybox \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/ipsec.d/generated /srv/www \
    && head -c 2000000 /dev/urandom > /srv/www/file.bin \
    && head -c 60000 /dev/urandom | base64 > /srv/www/index.html

CMD ["sleep", "infinity"]
