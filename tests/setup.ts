// tests/setup.ts - Optimized Docker-based test setup
import mongoose from 'mongoose';
import { CacheService } from '@/core/services/CacheService';
import { logger } from '@/core/infra/logger';
import { config } from '@/config/env';

// Increase timeout for Docker services
jest.setTimeout(60000);

// Global test setup
beforeAll(async () => {
    try {
        console.log('🔧 Setting up test environment...');

        // Wait a bit for Docker services to be fully ready
        await new Promise(resolve => setTimeout(resolve, 3000));

        // Configure mongoose for testing
        mongoose.set('strictQuery', false);

        // Connect to Docker MongoDB with retry logic
        let retries = 5;
        while (retries > 0) {
            try {
                await mongoose.connect(config.MONGODB_URI, {
                    serverSelectionTimeoutMS: 10000,
                    socketTimeoutMS: 45000,
                    maxPoolSize: 10,
                    minPoolSize: 5
                });
                console.log('✅ Connected to test MongoDB');
                break;
            } catch (error) {
                retries--;
                console.log(`⏳ MongoDB connection attempt failed, ${retries} retries left...`);
                if (retries === 0) throw error;
                await new Promise(resolve => setTimeout(resolve, 2000));
            }
        }

        // Initialize cache service with retry logic
        retries = 5;
        while (retries > 0) {
            try {
                await CacheService.initialize();
                console.log('✅ Connected to test Redis');
                break;
            } catch (error) {
                retries--;
                console.log(`⏳ Redis connection attempt failed, ${retries} retries left...`);
                if (retries === 0) throw error;
                await new Promise(resolve => setTimeout(resolve, 2000));
            }
        }

        // Suppress console logs during tests for cleaner output
        if (process.env.NODE_ENV === 'test') {
            jest.spyOn(console, 'log').mockImplementation(() => {});
            jest.spyOn(console, 'warn').mockImplementation(() => {});
            jest.spyOn(logger, 'info').mockImplementation(() => ({} as any));
            jest.spyOn(logger, 'warn').mockImplementation(() => ({} as any));
        }

        console.log('✅ Test environment setup complete');
    } catch (error) {
        console.error('❌ Failed to setup test environment:', error);
        console.log('\n💡 Troubleshooting:');
        console.log('   1. Ensure Docker is running');
        console.log('   2. Run: docker-compose up -d mongo redis');
        console.log('   3. Wait for services to be healthy');
        console.log('   4. Check ports 27017 and 6379 are available');
        throw error;
    }
});

// Global test teardown
afterAll(async () => {
    try {
        console.log('🧹 Cleaning up test environment...');

        // Close database connections gracefully
        if (mongoose.connection.readyState !== 0) {
            await mongoose.disconnect();
            console.log('✅ Disconnected from MongoDB');
        }

        // Cleanup cache service
        try {
            await CacheService.cleanup();
            console.log('✅ Disconnected from Redis');
        } catch (error) {
            // Check if the error is an instance of Error
            if (error instanceof Error) {
                console.log('⚠️ Redis cleanup warning:', error.message);
            } else {
                console.log('⚠️ Redis cleanup warning:', error);
            }
        }

        // Restore console methods
        if (jest.isMockFunction(console.log)) {
            (console.log as jest.MockedFunction<typeof console.log>).mockRestore();
        }
        if (jest.isMockFunction(console.warn)) {
            (console.warn as jest.MockedFunction<typeof console.warn>).mockRestore();
        }

        console.log('✅ Test environment cleanup complete');
    } catch (error) {
        console.error('❌ Test teardown failed:', error);
    }
});

// Clear test database before each test file
beforeEach(async () => {
    try {
        if (mongoose.connection.readyState === 1) {
            // Clear all collections in test database
            const collections = mongoose.connection.collections;
            const clearPromises = Object.keys(collections).map(async (key) => {
                try {
                    await collections[key].deleteMany({});
                } catch (error) {
                    // Ignore errors for collections that don't exist
                    if (error instanceof Error && !error.message.includes('ns not found')) {
                        throw error;
                    }
                }
            });
            await Promise.all(clearPromises);
        }

        // Clear Redis cache
        try {
            if (CacheService.isConnected()) {
                await CacheService.clear();
            }
        } catch (error) {
            // Check if the error is an instance of Error
            if (error instanceof Error) {
                console.log('⚠️ Redis clear warning:', error.message);
            } else {
                console.log('⚠️ Redis clear warning:', error);
            }
        }
    } catch (error) {
        console.error('❌ Failed to clear test database:', error);
    }
});

// Handle unhandled promise rejections in tests
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Graceful shutdown handlers
process.on('SIGINT', async () => {
    console.log('\n🛑 Received SIGINT, shutting down gracefully...');
    await cleanup();
    process.exit(0);
});

process.on('SIGTERM', async () => {
    console.log('\n🛑 Received SIGTERM, shutting down gracefully...');
    await cleanup();
    process.exit(0);
});

async function cleanup() {
    try {
        if (mongoose.connection.readyState !== 0) {
            await mongoose.disconnect();
        }
        await CacheService.cleanup();
    } catch (error) {
        console.error('Cleanup error:', error);
    }
}