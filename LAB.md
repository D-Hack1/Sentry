# Capture Lab

An isolated Docker bridge (`br-ipsec`, `10.10.0.0/24`, no NAT, no default route) with
three containers:

| Container | IP | Role |
|---|---|---|
| `ipsec-initiator` | 10.10.0.2 | strongSwan IKE initiator + traffic generators (curl, iperf3, ffmpeg, ping) |
| `ipsec-responder` | 10.10.0.3 | strongSwan IKE responder + servers (busybox httpd, iperf3, UDP sinks) |
| `ipsec-monitor` | 10.10.0.4 | `tcpdump` / `tshark` in promiscuous mode on the bridge |

## Bring it up

```bash
./start.sh            # whole stack, lab included
# or only the lab:
make up               # builds the three images, starts all containers, enables promiscuous capture
```

Promiscuous capture needs the host bridge `br-ipsec` to flood frames to the monitor
(`make promisc`, also run by `start.sh`). On Docker Desktop (macOS/Windows) the bridge
lives inside the Docker VM, so this step may be skipped with a warning.

## Bring a tunnel up by hand

```bash
python capture/gen_config.py --mode tunnel --cipher aes256gcm --dh-group group19 --pfs yes
docker exec ipsec-responder bash -c 'cp /etc/ipsec.d/generated/ipsec.* /etc/ && ipsec restart'
docker exec ipsec-initiator bash -c 'cp /etc/ipsec.d/generated/ipsec.* /etc/ && ipsec restart'
docker exec ipsec-initiator ipsec up sentry
bash capture/verify_sa.sh 30                     # waits for the ESP SA on both ends
docker exec ipsec-initiator ip xfrm state        # inspect the SAs
```

Shells: `make shell-initiator`, `make shell-responder`, `make shell-monitor`.

## Capture

```bash
make capture SCENARIO=my_test        # starts tcpdump in the monitor (ESP + UDP 500/4500)
# ...generate traffic through the tunnel...
docker exec ipsec-monitor sh -c 'kill -INT $(pidof tcpdump)'
make replay SCENARIO=my_test         # print it with tshark
```

## Full capture matrix

```bash
make matrix          # = bash capture/run_matrix.sh
```

Cycles every mode × cipher × DH group × PFS combination (80 configs, plus
`EXTRA_SESSIONS`). For each one it writes the strongSwan config, brings the SA up,
generates one traffic class, and saves `capture/pcaps/<mode>_<cipher>_<dh>_<pfs>_<traffic>_<seq>.pcap`.
Tune it in `.env` (`MATRIX_*`, `TRAFFIC_SECONDS`, `SKIP_EXISTING`).

## Retrieve and use the PCAPs

`capture/pcaps/` is bind-mounted from the monitor, so files appear on the host directly
(they are git-ignored, so share the set separately). While `start.sh` is running, the
watcher picks up every new PCAP automatically and the session appears in the dashboard.
For training:

```bash
make labels && make verify && make features && make train && make evaluate
```

No lab? `python scripts/synth_pcap.py --traffic web` writes a synthetic IKEv2 + ESP
capture into `capture/pcaps/`, which goes through the same pipeline.
