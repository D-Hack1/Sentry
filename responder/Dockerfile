FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    strongswan=5.9.8-5+deb12u5 \
    strongswan-pki=5.9.8-5+deb12u5 \
    libstrongswan-extra-plugins=5.9.8-5+deb12u5 \
    libstrongswan-standard-plugins=5.9.8-5+deb12u5 \
    iproute2=6.1.0-3 \
    iputils-ping=3:20221126-1+deb12u1 \
    iperf3=3.12-1+deb12u2 \
    busybox=1:1.35.0-4+deb12u1+b1 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/ipsec.d/generated /srv/www \
    && head -c 2000000 /dev/urandom > /srv/www/file.bin \
    && head -c 60000 /dev/urandom | base64 > /srv/www/index.html

CMD ["sleep", "infinity"]
