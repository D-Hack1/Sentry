.PHONY: start start-nolab stop test e2e labels verify features train evaluate \
        up down capture replay matrix logs promisc shell-initiator shell-responder shell-monitor

-include .env
export

PY := .venv/bin/python

# ── Whole stack ──────────────────────────────────────────────────────────────
start:            ## bootstrap + start every service (infra, lab, app, dashboard)
	./start.sh

start-nolab:      ## same, without the strongSwan capture lab
	./start.sh --no-lab

stop:             ## stop every service (keeps Elasticsearch data)
	./stop.sh

test:             ## unit tests
	$(PY) -m pytest

e2e:              ## end-to-end test against a running stack
	$(PY) scripts/e2e_test.py

# ── Dataset + training ───────────────────────────────────────────────────────
labels:           ## label JSONs from capture-matrix PCAP names
	$(PY) data/make_labels.py --from-pcaps

verify:           ## check PCAP <-> label pairing
	$(PY) data/verify.py

features:         ## extract data/features/*.parquet from every PCAP (no Kafka)
	$(PY) -m features.watcher --replay $(PCAP_DIR) --no-kafka

train:            ## train all models (add ARGS=--skip-optuna for a fast run)
	$(PY) ml/train.py $(ARGS)

evaluate:         ## classification reports + confusion matrices
	$(PY) ml/evaluate.py

# ── Capture lab ──────────────────────────────────────────────────────────────

COMPOSE := docker compose

up:
	mkdir -p $(CONFIG_DIR)/initiator $(CONFIG_DIR)/responder $(PCAP_DIR)
	$(COMPOSE) up -d --build
	@sleep 3
	$(MAKE) promisc

down:
	$(COMPOSE) down -v

promisc:
	docker exec $(MONITOR_CONTAINER) ip link set eth0 promisc on
	docker run --rm --net=host --cap-add=NET_ADMIN sentry-monitor ip link set $(BRIDGE_NAME) type bridge ageing_time 0

capture:
	@if [ -z "$(SCENARIO)" ]; then echo "Usage: make capture SCENARIO=<name>"; exit 1; fi
	docker exec -d $(MONITOR_CONTAINER) tcpdump -Z root -i eth0 -w /data/capture/$(SCENARIO).pcap 'esp or udp port 500 or udp port 4500'

replay:
	@if [ -z "$(SCENARIO)" ]; then echo "Usage: make replay SCENARIO=<name>"; exit 1; fi
	docker exec $(MONITOR_CONTAINER) tshark -r /data/capture/$(SCENARIO).pcap

matrix:
	bash capture/run_matrix.sh

logs:
	$(COMPOSE) logs -f

shell-initiator:
	docker exec -it $(INITIATOR_CONTAINER) bash

shell-responder:
	docker exec -it $(RESPONDER_CONTAINER) bash

shell-monitor:
	docker exec -it $(MONITOR_CONTAINER) bash
