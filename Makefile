# =============================================================================
# Blue Team Detection Engineering Lab — Makefile
# =============================================================================

.PHONY: help setup setup-elastic setup-splunk setup-both setup-full start stop \
        down logs sim-logs status clean agent transpile-elastic transpile-splunk \
        share-check

# Default SIEM (override with: make setup SIEM=splunk)
SIEM ?= elastic

# All profiles for stop/down/clean operations
ALL_PROFILES = --profile elastic --profile splunk --profile cribl --profile simulator

help: ## Show this help
	@echo ""
	@echo "Blue Team Detection Engineering Lab"
	@echo "===================================="
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ─── Setup ───────────────────────────────────────────────────────
setup: ## Full setup (interactive — picks SIEM, installs deps, starts lab)
	@chmod +x setup.sh && ./setup.sh

setup-elastic: ## Setup with Elastic stack
	@chmod +x setup.sh && ./setup.sh --elastic

setup-splunk: ## Setup with Splunk stack
	@chmod +x setup.sh && ./setup.sh --splunk

setup-both: ## Setup with both Elastic and Splunk
	@chmod +x setup.sh && ./setup.sh --both

setup-full: ## Setup everything (both SIEMs + Cribl)
	@chmod +x setup.sh && ./setup.sh --full

# ─── Operations ──────────────────────────────────────────────────
start: ## Start lab services (SIEM=elastic|splunk|both)
	docker compose --profile $(SIEM) --profile simulator up -d

stop: ## Stop all lab services (keep data)
	docker compose $(ALL_PROFILES) stop

down: ## Stop and remove containers (keep data volumes)
	docker compose $(ALL_PROFILES) down

clean: ## Stop, remove containers AND delete all data
	docker compose $(ALL_PROFILES) down -v
	@echo "All data volumes deleted."

status: ## Show status of all services
	@docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"

# ─── Logs ────────────────────────────────────────────────────────
logs: ## Tail logs from all services
	docker compose $(ALL_PROFILES) logs -f --tail=50

sim-logs: ## Tail only the log simulator output
	docker compose logs -f log-simulator --tail=50

# ─── Detection Engineering ───────────────────────────────────────
agent: ## Launch Claude Code in this directory
	@echo "Starting Claude Code..."
	@echo "Tip: paste the first-run prompt from PROMPTS.md"
	claude

transpile-elastic: ## Transpile all Sigma rules to Elasticsearch
	@find detections -name "*.yml" -not -path "*/compiled/*" | while read rule; do \
		echo "Transpiling: $$rule"; \
		sigma convert -t lucene -p ecs_windows "$$rule" 2>/dev/null || echo "  (failed)"; \
	done

transpile-splunk: ## Transpile all Sigma rules to Splunk SPL
	@find detections -name "*.yml" -not -path "*/compiled/*" | while read rule; do \
		echo "Transpiling: $$rule"; \
		sigma convert -t splunk --without-pipeline "$$rule" 2>/dev/null || echo "  (failed)"; \
	done

# ─── Data ────────────────────────────────────────────────────────
ingest-samples: ## Load sample Attack Range data into SIEMs
	@chmod +x pipeline/fetch-attack-range-data.sh && bash pipeline/fetch-attack-range-data.sh samples

# ─── Sharing ─────────────────────────────────────────────────────
share-check: ## Verify the project is ready to share (clean, documented)
	@echo "Checking share readiness..."
	@test -f README.md && echo "  OK: README.md" || echo "  MISSING: README.md"
	@test -f setup.sh && echo "  OK: setup.sh" || echo "  MISSING: setup.sh"
	@test -f docker-compose.yml && echo "  OK: docker-compose.yml" || echo "  MISSING: docker-compose.yml"
	@test -f CLAUDE.md && echo "  OK: CLAUDE.md" || echo "  MISSING: CLAUDE.md"
	@test -f PROMPTS.md && echo "  OK: PROMPTS.md" || echo "  MISSING: PROMPTS.md"
	@test ! -f .env && echo "  OK: No .env file" || echo "  WARN: .env exists — don't commit secrets!"
	@echo ""
	@echo "To share: push to GitHub and others just run:"
	@echo "  git clone <repo> && cd ai-detection-engineering && make setup"
