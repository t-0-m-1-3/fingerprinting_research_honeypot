.PHONY: help honeypot scan-all scan-cat1 scan-cat2 scan-cat3 scan-cat4 scan-cat5 scan-quick dry-run clean

HARNESS = python3 -m harness.run

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

honeypot: ## Start the honeypot (docker compose)
	docker compose -f honeypot/docker-compose.yml up -d --build

scan-quick: ## Run a quick validation scan (curl only)
	$(HARNESS) --tools curl

scan-cat1: ## Run all Category 1 web scanners
	$(HARNESS) --category cat1-scanners

scan-cat2: ## Run all Category 2 recon tools
	$(HARNESS) --category cat2-recon

scan-cat3: ## Run all Category 3 browser automation
	$(HARNESS) --category cat3-browsers

scan-cat4: ## Run all Category 4 evasion tools
	$(HARNESS) --category cat4-evasion

scan-cat5: ## Run all Category 5 vulnerability scanners
	$(HARNESS) --category cat5-vulnscanners

scan-all: ## Run all tools across all categories
	$(HARNESS) --all

dry-run: ## Show what --all would run without executing
	$(HARNESS) --all --dry-run

clean: ## Stop honeypot and remove harness network
	docker compose -f honeypot/docker-compose.yml down 2>/dev/null || true
	docker network rm harness-net 2>/dev/null || true
	@echo "Cleaned up. PCAPs and reports preserved in harness/captures/ and harness/reports/"
