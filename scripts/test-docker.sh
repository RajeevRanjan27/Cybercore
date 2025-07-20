#!/bin/bash

# Exit on any error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[TEST-DOCKER]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to cleanup on exit
cleanup() {
    print_status "Cleaning up Docker services..."
    docker-compose down --remove-orphans
    docker-compose -f docker-compose.yml down --remove-orphans 2>/dev/null || true
}

# Set trap for cleanup on script exit
trap cleanup EXIT

# Function to check if Docker is running
check_docker() {
    print_status "Checking Docker availability..."
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker first."
        exit 1
    fi
    print_success "Docker is running"
}

# Function to wait for healthy services
wait_for_healthy_services() {
    print_status "Waiting for services to be healthy..."

    local max_attempts=30
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        local mongo_healthy=false
        local redis_healthy=false

        # Check MongoDB health
        if docker-compose exec -T mongo mongosh --eval "db.runCommand('ping').ok" --quiet >/dev/null 2>&1; then
            mongo_healthy=true
        fi

        # Check Redis health
        if docker-compose exec -T redis redis-cli ping >/dev/null 2>&1; then
            redis_healthy=true
        fi

        if [ "$mongo_healthy" = true ] && [ "$redis_healthy" = true ]; then
            print_success "All services are healthy!"
            return 0
        fi

        print_status "Services not yet healthy (attempt $attempt/$max_attempts)..."
        sleep 2
        ((attempt++))
    done

    print_error "Services failed to become healthy within timeout"
    return 1
}

# Main execution
main() {
    print_status "🚀 Starting Docker-based test environment..."

    # Check Docker availability
    check_docker

    # Parse command line arguments
    TEST_TYPE=${1:-"all"}

    print_status "Test type: $TEST_TYPE"

    # Start Docker services
    print_status "Starting Docker services..."
    docker-compose up -d mongo redis

    # Wait for services to be healthy
    if ! wait_for_healthy_services; then
        print_error "Failed to start required services"
        exit 1
    fi

    # Run the wait script to double-check connectivity
    print_status "Verifying service connectivity..."
    if ! npm run test:wait; then
        print_error "Service connectivity check failed"
        exit 1
    fi

    print_success "Services are ready!"

    # Run tests based on type
    print_status "Running tests..."

    case $TEST_TYPE in
        "unit")
            print_status "Running unit tests..."
            npm run test:unit
            ;;
        "integration")
            print_status "Running integration tests..."
            npm run test:integration
            ;;
        "e2e")
            print_status "Running e2e tests..."
            npm run test:e2e
            ;;
        "coverage")
            print_status "Running tests with coverage..."
            npm run test:coverage
            ;;
        "security")
            print_status "Running security tests..."
            npm test -- --testPathPattern=security
            ;;
        "performance")
            print_status "Running performance tests..."
            npm test -- --testPathPattern=performance
            ;;
        "all"|*)
            print_status "Running all tests..."
            npm run test:ci
            ;;
    esac

    TEST_EXIT_CODE=$?

    if [ $TEST_EXIT_CODE -eq 0 ]; then
        print_success "All tests passed! 🎉"
    else
        print_error "Some tests failed! ❌"
    fi

    # Generate test report if coverage was run
    if [ "$TEST_TYPE" = "coverage" ] || [ "$TEST_TYPE" = "all" ]; then
        if [ -d "coverage" ]; then
            print_status "Test coverage report generated in ./coverage/"
            print_status "Open ./coverage/lcov-report/index.html to view detailed coverage"
        fi
    fi

    return $TEST_EXIT_CODE
}

# Run main function
main "$@"