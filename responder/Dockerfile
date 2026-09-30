FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    strongswan=5.9.8-5+deb12u5 \
    strongswan-pki=5.9.8-5+deb12u5 \
    libstrongswan-extra-plugins=5.9.8-5+deb12u5 \
    libstrongswan-standard-plugins=5.9.8-5+deb12u5 \
    iproute2=6.1.0-3 \
    iputils-ping=3:20221126-1+deb12u1 \
    python3=3.11.2-1+b1 \
    nginx-light \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/ipsec.d/generated /srv/www \
    && head -c 52428800 /dev/urandom > /srv/www/random_50mb.bin

COPY nginx-file-transfer.conf /etc/nginx-file-transfer.conf

CMD ["sleep", "infinity"]
