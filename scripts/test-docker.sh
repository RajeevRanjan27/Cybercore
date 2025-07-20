#!/bin/bash

# ============================================================================
# test-docker.sh
#
# This script orchestrates running the test suite within a Docker environment.
# It ensures a clean, consistent environment for testing by managing Docker
# services and running specific test commands.
#
# Usage:
#   ./scripts/test-docker.sh [test_type]
#
# Arguments:
#   test_type (optional): The type of test to run. Defaults to 'all'.
#     - all: Runs the full CI suite (unit, integration, etc.) with coverage.
#     - unit: Runs only unit tests.
#     - integration: Runs only integration tests.
#     - e2e: Runs only end-to-end tests.
#     - security: Runs only security tests.
#     - performance: Runs only performance tests.
#     - coverage: Runs all tests and generates a coverage report.
#
# ============================================================================

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
DOCKER_COMPOSE_FILE="docker-compose.test.yml"
APP_SERVICE_NAME="app-test"

# --- Colors for output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Helper Functions ---
print_status() {
    echo -e "${BLUE}[TEST-DOCKER]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

cleanup() {
    print_status "Performing cleanup..."
    docker-compose -f "$DOCKER_COMPOSE_FILE" down -v --remove-orphans
    print_status "Cleanup complete."
}

# --- Main Logic ---

# Trap EXIT signal to ensure cleanup runs
trap cleanup EXIT

# 1. Check for Docker
print_status "Checking for Docker..."
if ! command -v docker &> /dev/null || ! command -v docker-compose &> /dev/null; then
    print_error "Docker and docker-compose are required. Please install them."
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    print_error "Docker daemon is not running. Please start Docker."
    exit 1
fi
print_success "Docker is ready."

# 2. Determine Test Command
TEST_TYPE=${1:-"all"}
NPM_COMMAND="test:ci" # Default to full CI run

case $TEST_TYPE in
    "unit"|"integration"|"e2e"|"security"|"performance"|"coverage")
        NPM_COMMAND="test:$TEST_TYPE"
        ;;
    "all")
        NPM_COMMAND="test:ci"
        ;;
    *)
        print_error "Invalid test type '$TEST_TYPE'. Valid types are: unit, integration, e2e, security, performance, coverage, all."
        exit 1
        ;;
esac

print_status "Test type selected: ${YELLOW}$TEST_TYPE${NC}"
print_status "NPM command to run: ${YELLOW}npm run $NPM_COMMAND${NC}"

# 3. Build and Run Docker Compose
print_status "Building and starting test containers..."
# Using --abort-on-container-exit to automatically stop all containers when the test runner finishes.
# The exit code of the test runner will be the exit code of the `up` command.
docker-compose -f "$DOCKER_COMPOSE_FILE" up --build --abort-on-container-exit

# Capture the exit code of the app-test container
# The `docker-compose up` command with --abort-on-container-exit will propagate the exit code.
EXIT_CODE=$?

# 4. Final Report
echo # Newline for readability
if [ $EXIT_CODE -eq 0 ]; then
    print_success "All tests passed! 🎉"
else
    print_error "Tests failed with exit code $EXIT_CODE. ❌"
fi

# The 'trap' will handle the cleanup.
exit $EXIT_CODE
