.PHONY: help setup dev test build deploy clean logs

help:
	@echo "Rupert Security Conductor - Development Commands"
	@echo ""
	@echo "Setup:"
	@echo "  make setup         - Setup local development environment"
	@echo "  make dev           - Start local development server"
	@echo ""
	@echo "Development:"
	@echo "  make test          - Run tests"
	@echo "  make format        - Format code with black"
	@echo "  make lint          - Check code with pylint"
	@echo "  make type-check    - Run type checking with mypy"
	@echo ""
	@echo "Docker & Deployment:"
	@echo "  make build         - Build Docker image"
	@echo "  make deploy        - Deploy to GCP Cloud Run"
	@echo "  make logs          - View Cloud Run logs"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean         - Remove build artifacts and cache"
	@echo "  make clean-all     - Remove everything including venv"

setup:
	bash infra/scripts/setup-dev.sh

dev:
	source .venv/bin/activate && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

dev-docker:
	docker-compose up --build

test:
	source .venv/bin/activate && pytest -v --cov=app

format:
	source .venv/bin/activate && black app/ infra/

lint:
	source .venv/bin/activate && pylint app/ || true

type-check:
	source .venv/bin/activate && mypy app/ || true

build:
	docker build -t security-conductor:latest .

build-no-cache:
	docker build --no-cache -t security-conductor:latest .

deploy:
	@if [ -z "$(GCP_PROJECT_ID)" ]; then \
		echo "Error: GCP_PROJECT_ID not set"; \
		echo "Usage: make deploy GCP_PROJECT_ID=your-project-id [GCP_REGION=us-central1]"; \
		exit 1; \
	fi
	bash infra/scripts/deploy.sh $(GCP_PROJECT_ID) $(GCP_REGION)

logs:
	@if [ -z "$(SERVICE_NAME)" ]; then \
		gcloud logging read "resource.labels.service_name=rupert-security-conductor" --limit 50 --format "table(timestamp,severity,jsonPayload.message)"; \
	else \
		gcloud logging read "resource.labels.service_name=$(SERVICE_NAME)" --limit 50 --format "table(timestamp,severity,jsonPayload.message)"; \
	fi

logs-tail:
	gcloud logging read "resource.labels.service_name=rupert-security-conductor" \
		--limit 20 \
		--format "table(timestamp,severity,jsonPayload.message)" \
		--follow

logs-scan:
	@if [ -z "$(SCAN_ID)" ]; then \
		echo "Usage: make logs-scan SCAN_ID=<your-scan-id>"; \
		exit 1; \
	fi
	gcloud logging read "jsonPayload.scan_id=$(SCAN_ID)" --format json

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .coverage htmlcov/

clean-all: clean
	rm -rf .venv/
	rm -rf build/ dist/ *.egg-info

.DEFAULT_GOAL := help
