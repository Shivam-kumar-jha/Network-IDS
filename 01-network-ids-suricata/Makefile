.DEFAULT_GOAL := help
SHELL := /bin/bash

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	 | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

setup:  ## Install Suricata + rules (macOS/Homebrew)
	bash scripts/setup.sh

demo:  ## Run the full pipeline end to end
	bash scripts/demo.sh

sample:  ## Regenerate synthetic eve.json
	python3 scripts/gen_sample_eve.py -o logs/eve.json -n 120

pcap:  ## Build the ground-truth test PCAP
	python3 scripts/gen_test_pcap.py -o data/output.pcap --truth data/ground_truth.csv

live:  ## Full real run: PCAP -> Suricata -> parse -> score
	python3 scripts/gen_test_pcap.py -o data/output.pcap --truth data/ground_truth.csv
	bash scripts/run_suricata.sh -r data/output.pcap
	python3 scripts/parse_alerts.py -i logs/eve.json -o out/alerts.csv --json out/summary.json
	python3 scripts/score_detection.py --truth data/ground_truth.csv -i logs/eve.json

score:  ## Score last run against ground truth
	python3 scripts/score_detection.py --truth data/ground_truth.csv -i logs/eve.json

parse:  ## Parse logs/eve.json into out/
	python3 scripts/parse_alerts.py -i logs/eve.json -o out/alerts.csv --json out/summary.json

validate:  ## Check config + rule syntax (suricata -T)
	suricata -T -c config/suricata.yaml -S rules/local.rules

test:  ## Verify the parser against seeded ground truth
	@python3 scripts/gen_sample_eve.py -o /tmp/_t.json -n 120 --seed 1337 >/dev/null
	@python3 scripts/parse_alerts.py -i /tmp/_t.json -o /tmp/_t.csv -q >/dev/null
	@n=$$(($$(wc -l < /tmp/_t.csv) - 1)); \
	 if [ $$n -eq 120 ]; then echo "PASS: 120 alerts extracted"; \
	 else echo "FAIL: got $$n, expected 120"; exit 1; fi

clean:  ## Remove generated logs and artifacts
	rm -rf logs/*.json logs/*.log out/
	@echo "cleaned"

.PHONY: help setup demo sample pcap live score parse validate test clean
