# CyberCore API Test Makefile

.PHONY: help test test-unit test-integration test-coverage test-security test-performance
.PHONY: services-up services-down services-logs services-clean services-status
.PHONY: install build clean lint format

# Default target
help: ## Show this help message
	@echo "CyberCore API Test Commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Installation and Setup
install: ## Install dependencies
	npm install

build: ## Build the application
	npm run build

clean: ## Clean build artifacts and node_modules
	npm run clean
	rm -rf node_modules

# Testing Commands
test: ## Run all tests with Docker
	npm run test:docker

test-unit: ## Run unit tests only
	npm run test:docker:unit

test-integration: ## Run integration tests only
	npm run test:docker:integration

test-e2e: ## Run end-to-end tests
	npm run test:docker:e2e

test-coverage: ## Run tests with coverage report
	npm run test:docker:coverage

test-security: ## Run security tests
	npm run test:docker:security

test-performance: ## Run performance tests
	npm run test:docker:performance

test-quick: ## Quick unit tests for development
	npm run test:quick

test-full: ## Full test suite with coverage
	npm run test:full

# Docker Services Management
services-up: ## Start MongoDB and Redis services
	npm run docker:services:up

services-down: ## Stop all Docker services
	npm run docker:services:down

services-logs: ## View Docker service logs
	npm run docker:services:logs

services-clean: ## Stop services and remove volumes
	npm run docker:services:clean

services-status: ## Check Docker service status
	docker-compose ps

services-health: ## Check service health
	npm run test:wait

# Development Tools
lint: ## Run ESLint
	npm run lint

lint-fix: ## Run ESLint with auto-fix
	npm run lint:fix

format: ## Format code with Prettier
	npm run format

format-check: ## Check code formatting
	npm run format:check

type-check: ## Run TypeScript type checking
	npm run type-check

# Development Workflow
dev-setup: install services-up services-health ## Complete development setup
	@echo "✅ Development environment ready!"

dev-test: services-up test-unit ## Quick development testing

dev-clean: services-down clean ## Clean development environment

# CI/CD Commands
ci-test: ## Run CI test suite
	npm run test:ci

ci-lint: ## Run CI linting
	npm run lint
	npm run format:check
	npm run type-check

ci-security: ## Run CI security checks
	npm run security:check

# Utility Commands
logs: ## Show application logs (if running)
	npm run logs:tail

health: ## Check application health
	npm run health:check

# Database Management
db-seed: ## Seed test database
	npm run db:seed

db-reset: ## Reset test database
	npm run db:reset

# Quick Aliases
up: services-up ## Alias for services-up
down: services-down ## Alias for services-down
t: test-unit ## Alias for test-unit
tc: test-coverage ## Alias for test-coverage

# Help target (make this the default)
.DEFAULT_GOAL := help