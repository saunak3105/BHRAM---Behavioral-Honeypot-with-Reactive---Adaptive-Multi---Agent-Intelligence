# =============================================================================
# BHRAM — Makefile
# Behavioral Honeypot with Reactive-Adaptive Multi-Agent Intelligence
# =============================================================================

.PHONY: help setup up down restart logs status test clean validate build pull \
        shell-api shell-web shell-db api-docs env-check

COMPOSE := docker compose
PROJECT  := bhram
ENV_FILE := .env

## ── Help ─────────────────────────────────────────────────────────────────────
help: ## Show this help message
	@echo ""
	@echo "  ██████╗ ██╗  ██╗██████╗  █████╗ ███╗   ███╗"
	@echo "  ██╔══██╗██║  ██║██╔══██╗██╔══██╗████╗ ████║"
	@echo "  ██████╔╝███████║██████╔╝███████║██╔████╔██║"
	@echo "  ██╔══██╗██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║"
	@echo "  ██████╔╝██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║"
	@echo "  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝"
	@echo ""
	@echo "  Behavioral Honeypot with Reactive-Adaptive Multi-Agent Intelligence"
	@echo "  ─────────────────────────────────────────────────────────────────────"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""

## ── Setup ────────────────────────────────────────────────────────────────────
setup: ## First-time setup: copy .env.example → .env
	@if [ ! -f $(ENV_FILE) ]; then \
		cp .env.example $(ENV_FILE); \
		echo "  ✓ Created .env from .env.example — edit it before starting."; \
	else \
		echo "  ✓ .env already exists."; \
	fi
	@mkdir -p data/cowrie/logs data/decoy-files

## ── Docker lifecycle ─────────────────────────────────────────────────────────
build: ## Build all Docker images
	$(COMPOSE) build

pull: ## Pull base images
	$(COMPOSE) pull --ignore-buildable

up: ## Start all services (detached)
	$(COMPOSE) up -d --build
	@echo ""
	@echo "  BHRAM is starting. Use 'make status' to check health."
	@echo "  Web Application : http://localhost:8080"
	@echo "  BHRAM API       : http://localhost:8000"
	@echo "  API Docs        : http://localhost:8000/docs"
	@echo "  SSH Honeypot    : ssh root@localhost -p 2222"
	@echo "  File Server     : http://localhost:8081  (loopback only)"
	@echo ""

down: ## Stop and remove all containers
	$(COMPOSE) down

restart: ## Restart all services
	$(COMPOSE) restart

clean: ## Stop containers and remove volumes (WARNING: destroys data)
	$(COMPOSE) down -v --remove-orphans
	@echo "  ✓ All containers, volumes, and networks removed."

## ── Status ───────────────────────────────────────────────────────────────────
status: ## Show container status and health
	$(COMPOSE) ps
	@echo ""

logs: ## Tail logs from all services
	$(COMPOSE) logs -f

logs-api: ## Tail BHRAM API logs
	$(COMPOSE) logs -f bhram-api

logs-web: ## Tail web application logs
	$(COMPOSE) logs -f web

logs-cowrie: ## Tail Cowrie SSH honeypot logs
	$(COMPOSE) logs -f cowrie

logs-db: ## Tail PostgreSQL logs
	$(COMPOSE) logs -f postgres

## ── Validation ───────────────────────────────────────────────────────────────
validate: ## Validate Docker Compose configuration
	$(COMPOSE) config --quiet && echo "  ✓ compose.yaml is valid."

env-check: ## Check that .env exists
	@if [ -f $(ENV_FILE) ]; then \
		echo "  ✓ .env found."; \
	else \
		echo "  ✗ .env missing — run 'make setup' first."; \
		exit 1; \
	fi

health-check: ## Check all service health endpoints
	@echo "  Checking BHRAM API health..."
	@curl -sf http://localhost:8000/health | python3 -m json.tool || echo "  ✗ API not reachable"
	@echo ""
	@echo "  Checking Web Application..."
	@curl -sf -o /dev/null -w "  HTTP %{http_code}\n" http://localhost:8080/ || echo "  ✗ Web not reachable"
	@echo ""
	@echo "  Checking File Server..."
	@curl -sf http://localhost:8081/health | python3 -m json.tool || echo "  ✗ File server not reachable"

## ── Shell access ─────────────────────────────────────────────────────────────
shell-api: ## Open shell inside bhram-api container
	$(COMPOSE) exec bhram-api /bin/bash

shell-web: ## Open shell inside web container
	$(COMPOSE) exec web /bin/bash

shell-db: ## Open psql inside postgres container
	$(COMPOSE) exec postgres psql -U ${POSTGRES_USER:-bhram_user} -d ${POSTGRES_DB:-bhram_db}

shell-cowrie: ## Open shell inside cowrie container
	$(COMPOSE) exec cowrie /bin/bash

## ── API Docs ─────────────────────────────────────────────────────────────────
api-docs: ## Open API documentation in browser
	@echo "  BHRAM API Docs: http://localhost:8000/docs"
	@echo "  OpenAPI JSON  : http://localhost:8000/openapi.json"

## ── Testing ──────────────────────────────────────────────────────────────────
test: ## Run all BHRAM tests (requires services to be running)
	@echo "  Running BHRAM test suite..."
	cd tests && python3 -m pytest -v --tb=short
	@echo ""

test-unit: ## Run unit tests only (no Docker required)
	cd tests && python3 -m pytest -v --tb=short -m unit

test-integration: ## Run integration tests (Docker required)
	cd tests && python3 -m pytest -v --tb=short -m integration

## ── Utilities ────────────────────────────────────────────────────────────────
tree: ## Show project directory tree
	@find . -not -path './.git/*' -not -path './data/postgres/*' \
		-not -path './__pycache__/*' -not -path './.env' | \
		sort | sed 's|[^/]*/|  |g' | head -100
