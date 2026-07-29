.PHONY: test test-integration test-security test-all security-scan lint typecheck build up down logs test-docker prod-up

test:
	pytest tests/unit -v --tb=short

test-integration:
	pytest tests/integration -v --tb=short

test-security:
	pytest tests/security -v --tb=short

test-all:
	pytest tests/ -v --tb=short --cov=ragin --cov-report=term-missing

security-scan:
	bash scripts/security_scan.sh

lint:
	ruff check ragin/ tests/

typecheck:
	mypy ragin/ --ignore-missing-imports

# Docker
build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f

test-docker:
	docker compose -f docker-compose.yml -f docker-compose.test.yml up --build --abort-on-container-exit

prod-up:
	docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
