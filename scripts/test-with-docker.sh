#!/bin/bash

echo "🚀 Starting Docker services for testing..."

# Start services
docker-compose -f docker-compose.yml up -d mongo redis

# Wait for services
echo "⏳ Waiting for services to be ready..."
npm run test:wait

if [ $? -eq 0 ]; then
    echo "🧪 Running tests..."

    # Run tests based on argument
    case $1 in
        "unit")
            npm run test:unit
            ;;
        "integration")
            npm run test:integration
            ;;
        "coverage")
            npm run test:coverage
            ;;
        *)
            npm test
            ;;
    esac

    TEST_EXIT_CODE=$?

    echo "🧹 Cleaning up..."
    docker-compose -f docker-compose.yml stop mongo redis

    if [ $TEST_EXIT_CODE -eq 0 ]; then
        echo "✅ All tests passed!"
    else
        echo "❌ Some tests failed!"
        exit $TEST_EXIT_CODE
    fi
else
    echo "❌ Services failed to start!"
    docker-compose -f docker-compose.yml stop mongo redis
    exit 1
fi