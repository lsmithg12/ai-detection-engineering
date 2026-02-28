# =============================================================================
# Blue Team Detection Engineering Lab — Makefile
# =============================================================================

.PHONY: help setup setup-elastic setup-splunk setup-both start stop down \
        logs sim-logs status clean agent validate

# Default SIEM (override with: make setup SIEM=splunk)
SIEM ?= elastic

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

setup-full: ## Setup everything including Mythic prep
	@chmod +x setup.sh && ./setup.sh --full

# ─── Operations ──────────────────────────────────────────────────
start: ## Start all lab services
	docker compose --profile $(SIEM) --profile simulator up -d

stop: ## Stop all lab services (keep data)
	docker compose --profile elastic --profile splunk --profile simulator stop

down: ## Stop and remove containers (keep data volumes)
	docker compose --profile elastic --profile splunk --profile simulator down

clean: ## Stop, remove containers AND delete all data
	docker compose --profile elastic --profile splunk --profile simulator down -v
	@echo "All data volumes deleted."

status: ## Show status of all services
	@docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"

# ─── Logs ────────────────────────────────────────────────────────
logs: ## Tail logs from all services
	docker compose --profile elastic --profile splunk --profile simulator logs -f --tail=50

sim-logs: ## Tail only the log simulator output
	docker compose logs -f log-simulator --tail=50

# ─── Detection Engineering ───────────────────────────────────────
agent: ## Launch Claude Code in this directory
	@echo "Starting Claude Code..."
	@echo "Tip: paste the first-run prompt from PROMPTS.md"
	claude

validate: ## Validate all compiled detections against live data
	@for f in detections/*/compiled/*.json; do \
		[ -f "$$f" ] && echo "Validating: $$f" && bash pipeline/validate-detection.sh "$$f" || true; \
	done

transpile-elastic: ## Transpile all Sigma rules to Elasticsearch KQL
	@find detections -name "*.yml" -not -path "*/compiled/*" | while read rule; do \
		echo "Transpiling: $$rule"; \
		sigma convert -t elasticsearch -p ecs_windows "$$rule" 2>/dev/null || echo "  (failed)"; \
	done

transpile-splunk: ## Transpile all Sigma rules to Splunk SPL
	@find detections -name "*.yml" -not -path "*/compiled/*" | while read rule; do \
		echo "Transpiling: $$rule"; \
		sigma convert -t splunk "$$rule" 2>/dev/null || echo "  (failed)"; \
	done

# ─── Data ────────────────────────────────────────────────────────
ingest-mordor: ## Download and ingest OTRF/Mordor attack datasets
	@chmod +x pipeline/ingest-sample-data.sh && bash pipeline/ingest-sample-data.sh

# ─── Sharing ─────────────────────────────────────────────────────
share-check: ## Verify the project is ready to share (clean, documented)
	@echo "Checking share readiness..."
	@test -f README.md && echo "  ✅ README.md" || echo "  ❌ README.md missing"
	@test -f setup.sh && echo "  ✅ setup.sh" || echo "  ❌ setup.sh missing"
	@test -f docker-compose.yml && echo "  ✅ docker-compose.yml" || echo "  ❌ docker-compose.yml missing"
	@test -f CLAUDE.md && echo "  ✅ CLAUDE.md" || echo "  ❌ CLAUDE.md missing"
	@test -f PROMPTS.md && echo "  ✅ PROMPTS.md" || echo "  ❌ PROMPTS.md missing"
	@test ! -f .env && echo "  ✅ No .env file (secrets safe)" || echo "  ⚠️  .env exists — don't commit secrets!"
	@echo ""
	@echo "To share: push to GitHub and others just run:"
	@echo "  git clone <repo> && cd ai-detection-engineering && make setup"
