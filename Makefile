# =============================================================================
# CyberShield - Multi-Model Cyber Attack Response System
# Makefile
# =============================================================================

.PHONY: help install install-dev build up down restart recycle logs shell test lint format clean docs

# Default target
.DEFAULT_GOAL := help

# Colors for terminal output
CYAN := \033[36m
GREEN := \033[32m
YELLOW := \033[33m
RED := \033[31m
RESET := \033[0m

# =============================================================================
# Help
# =============================================================================
help: ## Show this help message
	@echo "$(CYAN)CyberShield - Multi-Model Cyber Attack Response System$(RESET)"
	@echo ""
	@echo "$(YELLOW)Usage:$(RESET)"
	@echo "  make [target]"
	@echo ""
	@echo "$(YELLOW)Targets:$(RESET)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(RESET) %s\n", $$1, $$2}'

# =============================================================================
# Installation
# =============================================================================
install: ## Install production dependencies
	pip install -r requirements.txt

install-dev: ## Install all dependencies including dev tools
	pip install -r requirements.txt
	pip install pytest pytest-asyncio pytest-cov httpx black ruff mypy pre-commit

setup-venv: ## Create and activate virtual environment
	python3 -m venv .venv
	@echo "$(GREEN)Virtual environment created. Activate with:$(RESET)"
	@echo "  source .venv/bin/activate"

# =============================================================================
# Docker Operations
# =============================================================================
build: ## Build Docker images
	docker-compose build

up: ## Start all services
	docker-compose up -d

up-logs: ## Start all services with logs
	docker-compose up

down: ## Stop all services
	docker-compose down

restart: ## Restart all services
	docker-compose restart

recycle: ## Full rebuild and restart (stop, rebuild, start)
	@echo "$(YELLOW)Recycling all services...$(RESET)"
	docker-compose down
	docker-compose build --no-cache
	docker-compose up -d
	@echo "$(GREEN)All services recycled$(RESET)"

recycle-quick: ## Quick recycle (no cache clear)
	@echo "$(YELLOW)Quick recycling...$(RESET)"
	docker-compose down && docker-compose build && docker-compose up -d
	@echo "$(GREEN)Services recycled$(RESET)"

logs: ## View logs from all services
	docker-compose logs -f

logs-api: ## View API service logs
	docker-compose logs -f cybershield-api

logs-ml: ## View ML service logs
	docker-compose logs -f cybershield-ml

logs-agents: ## View Agents service logs
	docker-compose logs -f cybershield-agents

logs-dashboard: ## View Dashboard service logs
	docker-compose logs -f cybershield-dashboard

shell: ## Open shell in API container
	docker-compose exec cybershield-api /bin/bash

shell-ml: ## Open shell in ML container
	docker-compose exec cybershield-ml /bin/bash

# =============================================================================
# Development
# =============================================================================
dev: ## Run development server locally
	uvicorn src.api.rest.app:app --host 0.0.0.0 --port 8000 --reload

run: ## Run the application locally
	python3 main.py

run-api: ## Run only the API server
	python3 main.py --mode api

run-dashboard: ## Run only the dashboard
	python3 main.py --mode dashboard

run-proxy: ## Run the reverse proxy gateway
	python3 main.py --mode proxy

run-full: ## Run API + Dashboard + Proxy (full stack)
	python3 main.py --mode full

# =============================================================================
# Reverse Proxy Gateway
# =============================================================================
proxy: ## Run proxy with default settings
	python3 -m src.proxy.server

proxy-passive: ## Run proxy in passive mode (logging only)
	python3 -m src.proxy.server --mode passive

proxy-strict: ## Run proxy in strict mode (block suspicious)
	python3 -m src.proxy.server --mode strict

proxy-dev: ## Run proxy with auto-reload for development
	python3 -m src.proxy.server --reload --log-level debug

proxy-status: ## Check proxy gateway status
	@echo "$(CYAN)Checking proxy status...$(RESET)"
	@curl -s http://localhost:8080/_proxy/status | python3 -m json.tool || echo "$(RED)Proxy not responding$(RESET)"

proxy-health: ## Check proxy upstream health
	@echo "$(CYAN)Checking upstream health...$(RESET)"
	@curl -s http://localhost:8080/_proxy/health | python3 -m json.tool || echo "$(RED)Proxy not responding$(RESET)"

proxy-stats: ## Show proxy inspector statistics
	@echo "$(CYAN)Inspector Statistics:$(RESET)"
	@curl -s http://localhost:8080/_proxy/inspector/stats | python3 -m json.tool || echo "$(RED)Proxy not responding$(RESET)"
	@echo ""
	@echo "$(CYAN)Forwarder Statistics:$(RESET)"
	@curl -s http://localhost:8080/_proxy/forwarder/stats | python3 -m json.tool || echo "$(RED)Proxy not responding$(RESET)"

# =============================================================================
# Testing
# =============================================================================
test: ## Run all tests
	pytest tests/ -v

test-e2e: ## Run end-to-end tests
	pytest tests/e2e/ -v

test-cov: ## Run tests with coverage report
	pytest tests/ -v --cov=src --cov-report=html --cov-report=term-missing

# =============================================================================
# Code Quality
# =============================================================================
lint: ## Run linter (ruff)
	ruff check src/ tests/

lint-fix: ## Run linter and fix issues
	ruff check src/ tests/ --fix

format: ## Format code (black)
	black src/ tests/

format-check: ## Check code formatting
	black src/ tests/ --check

typecheck: ## Run type checker (mypy)
	mypy src/

quality: lint format-check typecheck ## Run all code quality checks

# =============================================================================
# Cleanup
# =============================================================================
clean: ## Clean up generated files
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name ".coverage" -delete 2>/dev/null || true
	@echo "$(GREEN)Cleaned up generated files$(RESET)"

clean-docker: ## Clean up Docker resources
	docker-compose down -v --remove-orphans
	docker system prune -f
	@echo "$(GREEN)Cleaned up Docker resources$(RESET)"

clean-all: clean clean-docker ## Clean everything

# =============================================================================
# Redis Operations
# =============================================================================
redis-cli: ## Open Redis CLI
	docker-compose exec redis redis-cli

redis-flush: ## Flush Redis database
	docker-compose exec redis redis-cli FLUSHALL
	@echo "$(YELLOW)Redis database flushed$(RESET)"

# =============================================================================
# Utilities
# =============================================================================
status: ## Show status of all services
	docker-compose ps

health: ## Check health of all services
	@echo "$(CYAN)Checking service health...$(RESET)"
	@curl -s http://localhost:8000/api/v1/health | python3 -m json.tool || echo "$(RED)API not responding$(RESET)"

gen-key: ## Generate a new API key
	@python3 -c "import secrets; print(f'cs_{secrets.token_urlsafe(32)}')"

# =============================================================================
# Documentation
# =============================================================================
docs: ## Show getting started guide
	@cat docs/GETTING_STARTED.md
