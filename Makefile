.PHONY: up down capture replay matrix logs promisc shell-initiator shell-responder shell-monitor

include .env
export

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
